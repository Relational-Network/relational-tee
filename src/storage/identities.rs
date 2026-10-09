// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Identities: the internal `user_id` for each Entra `(tid, oid)`.
//!
//! - `identities/{h(tid ‖ oid)}.json`: the `user_id`, email, display name,
//!   roles as of the last sign-in, and first and last seen. Created once, at
//!   first sign-in or when an admin registers the person beforehand, then
//!   refreshed by compare-and-swap when the roles change and at most daily
//!   otherwise.
//! - `identities/email/{h(lowercase email)}.json`: the `user_id` for an
//!   email, and which identity holds it. Create-only.
//!
//! `h(x)` keeps Entra object IDs and emails out of object names. The
//! mapping never changes, so workers cache it without revalidating. A
//! token without an `email` claim gets no email index entry.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{Change, Storage, StoreError};
use crate::store::Created;

/// How long a sign-in leaves `last_seen` alone when the roles didn't change.
const REFRESH_AFTER: chrono::Duration = chrono::Duration::days(1);

/// One person, as the platform knows them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub roles: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// Registered by an admin and not signed in yet. The first sign-in
    /// keeps the `user_id`, so grants made before it are theirs.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pending: bool,
    /// The `user_id` of the admin who registered them, if one did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered_by: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct EmailEntry {
    user_id: String,
    /// The identity object's `h(tid ‖ oid)`.
    identity: String,
}

/// What a validated token says about its caller.
pub struct SignIn<'a> {
    pub tid: &'a str,
    pub oid: &'a str,
    pub email: &'a str,
    pub display_name: &'a str,
    pub roles: &'a [String],
}

/// Someone an admin found in Entra, before their first sign-in.
pub struct Registration<'a> {
    pub tid: &'a str,
    pub oid: &'a str,
    pub email: &'a str,
    pub display_name: &'a str,
    /// The admin's `user_id`.
    pub registered_by: &'a str,
}

/// What registering someone did.
#[derive(Debug)]
pub enum Registered {
    /// They're known now, pending their first sign-in.
    New(Identity),
    /// They were known already: registered or signed in.
    Known(Identity),
    /// Another identity holds the email.
    EmailTaken,
}

/// Identity storage.
pub struct Identities<'a> {
    s: &'a Storage,
}

fn identity_path(key: &str) -> String {
    format!("identities/{key}.json")
}

impl<'a> Identities<'a> {
    pub(crate) fn new(s: &'a Storage) -> Self {
        Self { s }
    }

    fn key(&self, tid: &str, oid: &str) -> String {
        self.s.state().index_hash(&format!("{tid}\n{oid}"))
    }

    fn email_path(&self, email: &str) -> String {
        format!(
            "identities/email/{}.json",
            self.s.state().index_hash(&email.to_lowercase())
        )
    }

    /// The caller's identity, created on their first sign-in. A concurrent
    /// first sign-in loses the create-only race and reads the winner's.
    pub async fn sign_in(&self, who: &SignIn<'_>) -> Result<Identity, StoreError> {
        let key = self.key(who.tid, who.oid);
        let path = identity_path(&key);
        let state = self.s.state();
        let now = Utc::now();
        if let Some(known) = state.get_immutable_json::<Identity>(&path).await? {
            if !known.pending && known.roles == who.roles && now - known.last_seen < REFRESH_AFTER {
                return Ok(known);
            }
            let refreshed = state
                .update_json::<Identity, StoreError>(&path, |i| {
                    if i.pending {
                        // The first sign-in of someone registered beforehand:
                        // the token now says who they are.
                        i.pending = false;
                        i.first_seen = now;
                        if !who.email.is_empty() {
                            i.email = who.email.to_string();
                        }
                        if !who.display_name.is_empty() {
                            i.display_name = who.display_name.to_string();
                        }
                    }
                    i.roles = who.roles.to_vec();
                    i.last_seen = now;
                    Ok(Change::Changed)
                })
                .await?
                .unwrap_or_else(|| known.clone());
            // A registered person's email may only now be known.
            if known.pending && !refreshed.email.is_empty() {
                let entry = EmailEntry {
                    user_id: refreshed.user_id.clone(),
                    identity: key,
                };
                state
                    .create_json(&self.email_path(&refreshed.email), &entry)
                    .await?;
            }
            return Ok(refreshed);
        }

        let new = Identity {
            user_id: uuid::Uuid::new_v4().to_string(),
            email: who.email.to_string(),
            display_name: who.display_name.to_string(),
            roles: who.roles.to_vec(),
            first_seen: now,
            last_seen: now,
            pending: false,
            registered_by: None,
        };
        let identity = match state.create_json(&path, &new).await? {
            Created::New(_) => new,
            Created::AlreadyExists => state
                .get_json::<Identity>(&path)
                .await?
                .map(|(i, _)| i)
                .ok_or_else(|| StoreError::Invalid("an identity vanished".into()))?,
        };
        if !identity.email.is_empty() {
            let entry = EmailEntry {
                user_id: identity.user_id.clone(),
                identity: key,
            };
            state
                .create_json(&self.email_path(&identity.email), &entry)
                .await?;
        }
        Ok(identity)
    }

    /// Make `who` known before their first sign-in, under the internal
    /// `user_id` their first sign-in will then have. Create-only, so
    /// registering again, or after they signed in, changes nothing.
    pub async fn register(&self, who: &Registration<'_>) -> Result<Registered, StoreError> {
        let key = self.key(who.tid, who.oid);
        let path = identity_path(&key);
        let state = self.s.state();
        if !who.email.is_empty() {
            let held = state
                .get_immutable_json::<EmailEntry>(&self.email_path(who.email))
                .await?;
            if held.is_some_and(|entry| entry.identity != key) {
                return Ok(Registered::EmailTaken);
            }
        }
        if let Some(known) = state.get_json::<Identity>(&path).await? {
            return Ok(Registered::Known(known.0));
        }
        let now = Utc::now();
        let new = Identity {
            user_id: uuid::Uuid::new_v4().to_string(),
            email: who.email.to_string(),
            display_name: who.display_name.to_string(),
            roles: Vec::new(),
            first_seen: now,
            last_seen: now,
            pending: true,
            registered_by: Some(who.registered_by.to_string()),
        };
        let identity = match state.create_json(&path, &new).await? {
            Created::New(_) => new,
            Created::AlreadyExists => {
                let (known, _) = state
                    .get_json::<Identity>(&path)
                    .await?
                    .ok_or_else(|| StoreError::Invalid("an identity vanished".into()))?;
                return Ok(Registered::Known(known));
            }
        };
        if !identity.email.is_empty() {
            let entry = EmailEntry {
                user_id: identity.user_id.clone(),
                identity: key,
            };
            state
                .create_json(&self.email_path(&identity.email), &entry)
                .await?;
        }
        Ok(Registered::New(identity))
    }

    /// The identity with this email, once its owner has signed in or been
    /// registered.
    pub async fn by_email(&self, email: &str) -> Result<Option<Identity>, StoreError> {
        if email.trim().is_empty() {
            return Ok(None);
        }
        let state = self.s.state();
        let Some(entry) = state
            .get_immutable_json::<EmailEntry>(&self.email_path(email))
            .await?
        else {
            return Ok(None);
        };
        Ok(state
            .get_json::<Identity>(&identity_path(&entry.identity))
            .await?
            .map(|(i, _)| i))
    }

    /// Every known identity, in object name order.
    pub async fn all(&self) -> Result<Vec<Identity>, StoreError> {
        self.s
            .state()
            .list_json("identities/", |p| p.ends_with(".json"))
            .await
    }

    /// The identity whose `user_id` this is. Identities are named by their
    /// Entra IDs, so this reads them all: fine for the pilot's users, whose
    /// unchanged documents come from the cache.
    pub async fn by_user_id(&self, user_id: &str) -> Result<Option<Identity>, StoreError> {
        Ok(self.all().await?.into_iter().find(|i| i.user_id == user_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests::two_workers;

    fn sign_in<'a>(oid: &'a str, email: &'a str, roles: &'a [String]) -> SignIn<'a> {
        SignIn {
            tid: "tenant-1",
            oid,
            email,
            display_name: "Ada",
            roles,
        }
    }

    #[tokio::test]
    async fn concurrent_first_sign_ins_create_one_user_id() {
        let (a, b, files) = two_workers();
        let roles = vec!["Admin".to_string()];
        let who = sign_in("oid-ada", "Ada@Example.com", &roles);
        let (ids_a, ids_b) = (a.identities(), b.identities());
        let (x, y) = tokio::join!(ids_a.sign_in(&who), ids_b.sign_in(&who));
        let (x, y) = (x.unwrap(), y.unwrap());
        assert_eq!(x.user_id, y.user_id);

        // Found by email, in any case, but only after signing in.
        let found = b
            .identities()
            .by_email("ada@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.user_id, x.user_id);
        assert!(b
            .identities()
            .by_email("bob@example.com")
            .await
            .unwrap()
            .is_none());
        assert_eq!(a.identities().all().await.unwrap().len(), 1);
        let by_id = b.identities().by_user_id(&x.user_id).await.unwrap();
        assert_eq!(by_id.map(|i| i.email), Some("Ada@Example.com".to_string()));
        assert!(b.identities().by_user_id("nobody").await.unwrap().is_none());

        // Object names carry neither the object ID nor the email.
        let names: Vec<_> = crate::store::ObjectStore::list(files.as_ref(), "identities/email/")
            .await
            .unwrap()
            .into_iter()
            .chain(
                crate::store::ObjectStore::list(files.as_ref(), "identities/")
                    .await
                    .unwrap(),
            )
            .map(|l| l.path)
            .collect();
        assert_eq!(names.len(), 2);
        assert!(names
            .iter()
            .all(|n| !n.contains("oid-ada") && !n.to_lowercase().contains("ada@")));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ten_concurrent_first_sign_ins_on_two_workers_create_one_user_id() {
        let (a, b, _files) = two_workers();
        let workers = [std::sync::Arc::new(a), std::sync::Arc::new(b)];
        let attempts: Vec<_> = (0..10)
            .map(|i| {
                let storage = workers[i % 2].clone();
                tokio::spawn(async move {
                    let roles = vec!["Admin".to_string()];
                    let who = sign_in("oid-ten", "ten@example.com", &roles);
                    storage.identities().sign_in(&who).await.unwrap().user_id
                })
            })
            .collect();
        let mut user_ids = std::collections::BTreeSet::new();
        for attempt in attempts {
            user_ids.insert(attempt.await.unwrap());
        }
        assert_eq!(user_ids.len(), 1, "{user_ids:?}");
        assert_eq!(workers[1].identities().all().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_role_change_refreshes_the_identity() {
        let (a, _, _files) = two_workers();
        let admin = vec!["Admin".to_string()];
        let first = a
            .identities()
            .sign_in(&sign_in("oid-bo", "bo@example.com", &admin))
            .await
            .unwrap();
        let none: Vec<String> = Vec::new();
        let later = a
            .identities()
            .sign_in(&sign_in("oid-bo", "bo@example.com", &none))
            .await
            .unwrap();
        assert_eq!(later.user_id, first.user_id);
        assert!(later.roles.is_empty());
    }

    #[tokio::test]
    async fn users_without_an_email_share_no_index_entry() {
        let (a, _, _files) = two_workers();
        let none: Vec<String> = Vec::new();
        let x = a
            .identities()
            .sign_in(&sign_in("oid-x", "", &none))
            .await
            .unwrap();
        let y = a
            .identities()
            .sign_in(&sign_in("oid-y", "", &none))
            .await
            .unwrap();
        assert_ne!(x.user_id, y.user_id);
        assert!(a.identities().by_email("").await.unwrap().is_none());
    }

    fn registration<'a>(oid: &'a str, email: &'a str) -> Registration<'a> {
        Registration {
            tid: "tenant-1",
            oid,
            email,
            display_name: "Blair Bravo",
            registered_by: "admin-1",
        }
    }

    #[tokio::test]
    async fn a_registered_user_keeps_their_user_id_at_first_sign_in() {
        let (a, b, _files) = two_workers();
        let Registered::New(registered) = a
            .identities()
            .register(&registration("oid-blair", "blair@example.com"))
            .await
            .unwrap()
        else {
            panic!("a new registration");
        };
        assert!(registered.pending);
        assert_eq!(registered.registered_by.as_deref(), Some("admin-1"));
        let found = b.identities().by_email("Blair@example.com").await.unwrap();
        assert_eq!(found.map(|i| i.user_id), Some(registered.user_id.clone()));

        // Registering again changes nothing.
        let again = b
            .identities()
            .register(&registration("oid-blair", "blair@example.com"))
            .await
            .unwrap();
        assert!(matches!(again, Registered::Known(i) if i.user_id == registered.user_id));

        // Their first sign-in is theirs, with what the token says.
        let roles = Vec::new();
        let mut who = sign_in("oid-blair", "b.bravo@example.com", &roles);
        who.display_name = "B. Bravo";
        let signed_in = b.identities().sign_in(&who).await.unwrap();
        assert_eq!(signed_in.user_id, registered.user_id);
        assert!(!signed_in.pending);
        assert_eq!(
            (signed_in.email.as_str(), signed_in.display_name.as_str()),
            ("b.bravo@example.com", "B. Bravo")
        );
        let by_new_email = a
            .identities()
            .by_email("b.bravo@example.com")
            .await
            .unwrap();
        assert_eq!(by_new_email.map(|i| i.user_id), Some(registered.user_id));
    }

    #[tokio::test]
    async fn an_email_another_user_holds_is_refused() {
        let (a, _, _files) = two_workers();
        let roles = Vec::new();
        a.identities()
            .sign_in(&sign_in("oid-ada", "ada@example.com", &roles))
            .await
            .unwrap();
        let taken = a
            .identities()
            .register(&registration("oid-other", "ADA@example.com"))
            .await
            .unwrap();
        assert!(matches!(taken, Registered::EmailTaken));
        // Registering someone who already signed in returns them.
        let known = a
            .identities()
            .register(&registration("oid-ada", "ada@example.com"))
            .await
            .unwrap();
        assert!(matches!(known, Registered::Known(i) if !i.pending));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn registering_and_signing_in_at_once_make_one_user_id() {
        let (a, b, _files) = two_workers();
        let (a, b) = (std::sync::Arc::new(a), std::sync::Arc::new(b));
        let registering = tokio::spawn(async move {
            match a
                .identities()
                .register(&registration("oid-race", "race@example.com"))
                .await
                .unwrap()
            {
                Registered::New(i) | Registered::Known(i) => i.user_id,
                Registered::EmailTaken => panic!("the email is the same user's"),
            }
        });
        let signing_in = tokio::spawn(async move {
            let roles = Vec::new();
            let who = sign_in("oid-race", "race@example.com", &roles);
            b.identities().sign_in(&who).await.unwrap().user_id
        });
        assert_eq!(registering.await.unwrap(), signing_in.await.unwrap());
    }
}
