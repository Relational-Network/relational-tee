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
//!
//! The first identity to claim an email holds it, and every write is
//! idempotent, so a request that died between the two writes is completed
//! by the next one. A sign-in claims its email after its identity exists,
//! and every sign-in completes a missing entry; one whose email another
//! identity holds still signs in, by its Entra IDs, but isn't what a
//! lookup by that email finds. A registration claims the email first, and
//! creates nothing if another identity holds it.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;

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

/// Who holds an email once a claim is done.
enum Claim {
    /// The identity that claimed it, under this `user_id`.
    Ours { user_id: String },
    /// Another identity.
    Theirs,
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

    /// Claim `email` for the identity `key`, as `user_id` unless it's
    /// claimed for `key` already. Idempotent, and decided by the store's
    /// create-only write when two identities claim it at once.
    async fn claim_email(
        &self,
        email: &str,
        key: &str,
        user_id: &str,
    ) -> Result<Claim, StoreError> {
        let path = self.email_path(email);
        let state = self.s.state();
        let held = |entry: EmailEntry| {
            if entry.identity == key {
                Claim::Ours {
                    user_id: entry.user_id,
                }
            } else {
                Claim::Theirs
            }
        };
        if let Some(entry) = state.get_immutable_json::<EmailEntry>(&path).await? {
            return Ok(held(entry));
        }
        let entry = EmailEntry {
            user_id: user_id.to_string(),
            identity: key.to_string(),
        };
        match state.create_json(&path, &entry).await? {
            Created::New(_) => Ok(Claim::Ours {
                user_id: entry.user_id,
            }),
            Created::AlreadyExists => state
                .get_immutable_json::<EmailEntry>(&path)
                .await?
                .map(held)
                .ok_or_else(|| StoreError::Invalid("an email entry vanished".into())),
        }
    }

    /// Complete `identity`'s email entry, if it has an email: a sign-in's
    /// last step, which a request that died before it leaves undone.
    async fn complete(&self, key: &str, identity: &Identity) -> Result<(), StoreError> {
        if identity.email.is_empty() {
            return Ok(());
        }
        if let Claim::Theirs = self
            .claim_email(&identity.email, key, &identity.user_id)
            .await?
        {
            warn!(
                user_id = %identity.user_id,
                "Another identity holds this user's email: looking them up by email finds that one"
            );
        }
        Ok(())
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
                self.complete(&key, &known).await?;
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
            self.complete(&key, &refreshed).await?;
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
        self.complete(&key, &identity).await?;
        Ok(identity)
    }

    /// Make `who` known before their first sign-in, under the internal
    /// `user_id` their first sign-in will then have. Create-only, so
    /// registering again, or after they signed in, changes nothing. The
    /// email is claimed first: if another identity holds it, nothing is
    /// created.
    pub async fn register(&self, who: &Registration<'_>) -> Result<Registered, StoreError> {
        let key = self.key(who.tid, who.oid);
        let path = identity_path(&key);
        let state = self.s.state();
        if let Some((known, _)) = state.get_json::<Identity>(&path).await? {
            self.complete(&key, &known).await?;
            return Ok(Registered::Known(known));
        }
        // A registration that died after its claim left the user_id to use.
        let mut user_id = uuid::Uuid::new_v4().to_string();
        if !who.email.is_empty() {
            match self.claim_email(who.email, &key, &user_id).await? {
                Claim::Ours { user_id: claimed } => user_id = claimed,
                Claim::Theirs => return Ok(Registered::EmailTaken),
            }
        }
        let now = Utc::now();
        let new = Identity {
            user_id,
            email: who.email.to_string(),
            display_name: who.display_name.to_string(),
            roles: Vec::new(),
            first_seen: now,
            last_seen: now,
            pending: true,
            registered_by: Some(who.registered_by.to_string()),
        };
        match state.create_json(&path, &new).await? {
            Created::New(_) => Ok(Registered::New(new)),
            // Their first sign-in, or another registration, came first.
            Created::AlreadyExists => {
                let (known, _) = state
                    .get_json::<Identity>(&path)
                    .await?
                    .ok_or_else(|| StoreError::Invalid("an identity vanished".into()))?;
                Ok(Registered::Known(known))
            }
        }
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
        assert_eq!(user_ids.len(), 1);
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

    #[tokio::test]
    async fn the_next_sign_in_completes_one_that_died_before_its_email_entry() {
        let (a, b, _files) = two_workers();
        let roles = Vec::new();
        let who = sign_in("oid-cut", "cut@example.com", &roles);
        // The first sign-in wrote its identity, and died.
        let now = Utc::now();
        let written = Identity {
            user_id: "u-cut".into(),
            email: "cut@example.com".into(),
            display_name: "Ada".into(),
            roles: Vec::new(),
            first_seen: now,
            last_seen: now,
            pending: false,
            registered_by: None,
        };
        let key = a.identities().key("tenant-1", "oid-cut");
        a.state()
            .create_json(&identity_path(&key), &written)
            .await
            .unwrap();
        assert!(b
            .identities()
            .by_email("cut@example.com")
            .await
            .unwrap()
            .is_none());

        let retried = b.identities().sign_in(&who).await.unwrap();
        assert_eq!(retried.user_id, "u-cut");
        let found = a.identities().by_email("CUT@example.com").await.unwrap();
        assert_eq!(found.map(|i| i.user_id).as_deref(), Some("u-cut"));
    }

    #[tokio::test]
    async fn a_retried_registration_completes_one_that_died_after_its_claim() {
        let (a, b, _files) = two_workers();
        // The registration claimed the email, and died.
        let ids = a.identities();
        let key = ids.key("tenant-1", "oid-half");
        assert!(matches!(
            ids.claim_email("half@example.com", &key, "u-half")
                .await
                .unwrap(),
            Claim::Ours { .. }
        ));
        assert!(b
            .identities()
            .by_email("half@example.com")
            .await
            .unwrap()
            .is_none());

        let Registered::New(registered) = b
            .identities()
            .register(&registration("oid-half", "half@example.com"))
            .await
            .unwrap()
        else {
            panic!("the retry creates the identity");
        };
        assert_eq!(registered.user_id, "u-half", "under the claimed user_id");
        let found = a.identities().by_email("half@example.com").await.unwrap();
        assert_eq!(found.map(|i| i.user_id).as_deref(), Some("u-half"));

        // A registration of someone whose entry is missing completes it too.
        let key = ids.key("tenant-1", "oid-bare");
        let bare = Identity {
            email: "bare@example.com".into(),
            user_id: "u-bare".into(),
            pending: true,
            ..registered
        };
        a.state()
            .create_json(&identity_path(&key), &bare)
            .await
            .unwrap();
        let again = b
            .identities()
            .register(&registration("oid-bare", "bare@example.com"))
            .await
            .unwrap();
        assert!(matches!(again, Registered::Known(i) if i.user_id == "u-bare"));
        let found = a.identities().by_email("bare@example.com").await.unwrap();
        assert_eq!(found.map(|i| i.user_id).as_deref(), Some("u-bare"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn of_two_registrations_of_one_email_at_once_exactly_one_succeeds() {
        let (a, b, _files) = two_workers();
        let (a, b) = (std::sync::Arc::new(a), std::sync::Arc::new(b));
        for round in 0..10 {
            let email = format!("both-{round}@example.com");
            let register = |storage: std::sync::Arc<Storage>, oid: String| {
                let email = email.clone();
                tokio::spawn(async move {
                    storage
                        .identities()
                        .register(&registration(&oid, &email))
                        .await
                        .unwrap()
                })
            };
            let first = register(a.clone(), format!("oid-x{round}"));
            let second = register(b.clone(), format!("oid-y{round}"));
            let outcomes = [first.await.unwrap(), second.await.unwrap()];
            let created: Vec<&Identity> = outcomes
                .iter()
                .filter_map(|o| match o {
                    Registered::New(i) => Some(i),
                    _ => None,
                })
                .collect();
            let taken = outcomes
                .iter()
                .filter(|o| matches!(o, Registered::EmailTaken))
                .count();
            assert_eq!((created.len(), taken), (1, 1), "round {round}");
            let found = a.identities().by_email(&email).await.unwrap().unwrap();
            assert_eq!(found.user_id, created[0].user_id, "round {round}");
        }
        assert_eq!(b.identities().all().await.unwrap().len(), 10, "no orphans");
    }

    #[tokio::test]
    async fn a_sign_in_whose_email_another_identity_holds_still_signs_in() {
        let (a, _, _files) = two_workers();
        let roles = Vec::new();
        let first = a
            .identities()
            .sign_in(&sign_in("oid-one", "shared@example.com", &roles))
            .await
            .unwrap();
        let second = a
            .identities()
            .sign_in(&sign_in("oid-two", "shared@example.com", &roles))
            .await
            .unwrap();
        assert_ne!(first.user_id, second.user_id);
        let found = a.identities().by_email("shared@example.com").await.unwrap();
        assert_eq!(
            found.map(|i| i.user_id),
            Some(first.user_id),
            "the first holds it"
        );
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
