// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Identities: the internal `user_id` for each Entra `(tid, oid)`.
//!
//! - `identities/{h(tid ‖ oid)}.json`: the `user_id`, email, display name,
//!   roles as of the last sign-in, and first and last seen. Created once at
//!   first sign-in, then refreshed by compare-and-swap when the roles change
//!   and at most daily otherwise.
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
            if known.roles == who.roles && now - known.last_seen < REFRESH_AFTER {
                return Ok(known);
            }
            let refreshed = state
                .update_json::<Identity, StoreError>(&path, |i| {
                    i.roles = who.roles.to_vec();
                    i.last_seen = now;
                    Ok(Change::Changed)
                })
                .await?;
            return Ok(refreshed.unwrap_or(known));
        }

        let new = Identity {
            user_id: uuid::Uuid::new_v4().to_string(),
            email: who.email.to_string(),
            display_name: who.display_name.to_string(),
            roles: who.roles.to_vec(),
            first_seen: now,
            last_seen: now,
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

    /// The identity with this email, once its owner has signed in.
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
}
