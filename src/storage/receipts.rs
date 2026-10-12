// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Transfer receipts, until the sweep returns their deposits:
//! `receipts/{seed}.json`, one per transfer, created before the transfer is
//! sent, so a transfer that lands after its request died still has its
//! deposit swept. A receipt stays while its request's idempotency record
//! does, since a retry could still come. The sweep marks a receipt swept
//! rather than deleting it, since the store has no delete; a storage
//! lifecycle rule expires old ones.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{id, Change, Storage, StoreError};

/// A transfer's receipt account, as its wallet derives it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// The seed of the receipt's address under the wallet; it names the
    /// record too.
    pub seed: String,
    pub wallet_id: String,
    pub address: String,
    /// The idempotency record of the transfer's request.
    pub record: String,
    pub created_at: DateTime<Utc>,
    /// When the sweep returned the deposit, or found the receipt absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swept_at: Option<DateTime<Utc>>,
    /// The sweep's transaction, if it sent one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sweep_signature: Option<String>,
}

fn path(seed: &str) -> Result<String, StoreError> {
    id(seed)
        .map(|seed| format!("receipts/{seed}.json"))
        .ok_or_else(|| StoreError::Invalid("a receipt seed can't name an object".into()))
}

/// Receipt storage.
pub struct Receipts<'a> {
    s: &'a Storage,
}

impl<'a> Receipts<'a> {
    pub(crate) fn new(s: &'a Storage) -> Self {
        Self { s }
    }

    /// Record `receipt`, once: a retry finds it recorded.
    pub async fn record(&self, receipt: &Receipt) -> Result<(), StoreError> {
        self.s
            .state()
            .create_json(&path(&receipt.seed)?, receipt)
            .await?;
        Ok(())
    }

    /// The receipts not yet swept that were created before `before` and
    /// whose request's idempotency record is gone.
    pub async fn due(&self, before: DateTime<Utc>) -> Result<Vec<Receipt>, StoreError> {
        let all: Vec<Receipt> = self
            .s
            .state()
            .list_json("receipts/", |p| p.ends_with(".json"))
            .await?;
        let mut due = Vec::new();
        for receipt in all {
            if receipt.swept_at.is_some() || receipt.created_at >= before {
                continue;
            }
            if self.s.state().read(&receipt.record).await?.is_none() {
                due.push(receipt);
            }
        }
        Ok(due)
    }

    /// Mark `seed`'s receipt swept, by `signature` if the sweep sent one.
    pub async fn swept(&self, seed: &str, signature: Option<&str>) -> Result<(), StoreError> {
        self.s
            .state()
            .update_json::<Receipt, StoreError>(&path(seed)?, |r| {
                if r.swept_at.is_some() {
                    return Ok(Change::Unchanged);
                }
                r.swept_at = Some(Utc::now());
                r.sweep_signature = signature.map(String::from);
                Ok(Change::Changed)
            })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests::files_storage;

    fn receipt(seed: &str, days_ago: i64) -> Receipt {
        Receipt {
            seed: seed.into(),
            wallet_id: "w-1".into(),
            address: format!("addr-{seed}"),
            record: format!("idempotency/u-1/{seed}.json"),
            created_at: Utc::now() - chrono::Duration::days(days_ago),
            swept_at: None,
            sweep_signature: None,
        }
    }

    #[tokio::test]
    async fn receipts_are_due_once_old_and_retries_are_over_until_swept() {
        let storage = files_storage();
        let receipts = storage.receipts();
        let (old, new, retried) = (receipt("aa01", 9), receipt("aa02", 1), receipt("aa03", 9));
        for r in [&old, &new, &retried] {
            receipts.record(r).await.unwrap();
        }
        // A retry records it again, harmlessly.
        receipts.record(&old).await.unwrap();
        // One request's idempotency record is still there: a retry could
        // still come, so its receipt stays.
        storage
            .state()
            .create(&retried.record, b"{}")
            .await
            .unwrap();

        let before = Utc::now() - chrono::Duration::days(8);
        assert_eq!(
            receipts.due(before).await.unwrap(),
            std::slice::from_ref(&old)
        );
        receipts.swept("aa01", Some("sig-sweep")).await.unwrap();
        receipts.swept("aa01", Some("sig-again")).await.unwrap();
        assert!(receipts.due(before).await.unwrap().is_empty());
        let stored: Vec<Receipt> = storage
            .state()
            .list_json("receipts/", |_| true)
            .await
            .unwrap();
        assert_eq!(stored[0].sweep_signature.as_deref(), Some("sig-sweep"));

        assert!(receipts.record(&receipt("../x", 9)).await.is_err());
    }
}
