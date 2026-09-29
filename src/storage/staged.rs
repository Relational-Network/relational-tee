// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Staged chain sagas: `staged/{op_id}.json`, create-only, written before a
//! saga sends anything. Each holds what the saga's commit will write and the
//! path of its idempotency record, which holds the signed transaction, so
//! the reconciler ([`crate::reconciler`]) can finish a saga whose request
//! died after the chain step. A lifecycle rule deletes them after 7 days;
//! nothing else does.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::pools::{PoolDoc, Upload};
use super::{Storage, StoreError};
use crate::store::Created;

/// What a saga's commit writes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Saga {
    /// A pool creation: the whole pool document, less its creation signature.
    Pool { pool: Box<PoolDoc> },
    /// An issuance: the upload to add to the pool's log, less its signature.
    Issue { pool_pda: String, upload: Upload },
}

/// A staged saga.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Staged {
    /// The idempotency record of the request that staged it.
    pub record: String,
    pub staged_at: DateTime<Utc>,
    pub saga: Saga,
}

/// Staged saga storage.
pub struct Sagas<'a> {
    s: &'a Storage,
}

fn path(op_id: &str) -> String {
    format!("staged/{op_id}.json")
}

impl<'a> Sagas<'a> {
    pub(crate) fn new(s: &'a Storage) -> Self {
        Self { s }
    }

    /// Stage `staged` as `op_id`, or return what an earlier attempt of the
    /// same request already staged there, which the saga must then use.
    pub async fn stage(&self, op_id: &str, staged: Staged) -> Result<Staged, StoreError> {
        let path = path(op_id);
        let state = self.s.state();
        match state.create_json(&path, &staged).await? {
            Created::New(_) => Ok(staged),
            Created::AlreadyExists => state
                .get_json::<Staged>(&path)
                .await?
                .map(|(earlier, _)| earlier)
                .ok_or_else(|| StoreError::Invalid(format!("staged saga {op_id} vanished"))),
        }
    }

    /// Every staged saga. Only changed ones are fetched.
    pub async fn all(&self) -> Result<Vec<Staged>, StoreError> {
        self.s
            .state()
            .list_json("staged/", |p| p.ends_with(".json"))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::pools::tests::upload;
    use crate::storage::tests::two_workers;

    #[tokio::test]
    async fn the_first_staged_saga_wins() {
        let (a, b, _files) = two_workers();
        let staged = |rows| Staged {
            record: "idempotency/u/x.json".into(),
            staged_at: Utc::now(),
            saga: Saga::Issue {
                pool_pda: "P1".into(),
                upload: upload("r1", rows),
            },
        };
        a.sagas().stage("issue-r1", staged(3)).await.unwrap();
        let again = b.sagas().stage("issue-r1", staged(9)).await.unwrap();
        let Saga::Issue { upload, .. } = again.saga else {
            panic!("an issuance");
        };
        assert_eq!(upload.rows, 3);
    }
}
