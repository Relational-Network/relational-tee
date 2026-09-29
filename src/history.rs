// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Wallet transaction history, read from Solana on demand.
//!
//! A page is `getSignaturesForAddress` (newest first, before the cursor)
//! followed by `getTransaction` for each signature; the cursor is the page's
//! last signature, which is Solana's own paging. Nothing stores a copy of the
//! chain. Each worker keeps pages for a short TTL and parsed transactions by
//! signature, so repeated page loads cost no RPC calls.

use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use futures_util::stream::{self, StreamExt, TryStreamExt};
use lru::LruCache;
use serde::Serialize;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use utoipa::ToSchema;

use crate::blockchain::rpc::TransactionDetail;
use crate::blockchain::SolanaClient;
use crate::error::ApiError;

/// `getTransaction` calls in flight at once for one page.
const FETCH_CONCURRENCY: usize = 4;

/// Whether a transfer was native SOL or an SPL token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    /// Native SOL.
    Native,
    /// An SPL token, identified by its mint address.
    SplToken(String),
}

/// Whether the transaction succeeded on-chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TxStatus {
    Confirmed,
    Failed,
}

/// One transaction, from one wallet's side.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct WalletTransaction {
    pub signature: String,
    pub wallet_id: String,
    pub from: String,
    pub to: String,
    /// The amount in whole units: SOL with 9 decimals, or the token's own.
    pub amount: String,
    /// The amount in lamports, for native SOL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_lamports: Option<u64>,
    pub token: TokenType,
    pub network: String,
    pub status: TxStatus,
    pub slot: u64,
    pub fee_lamports: u64,
    pub explorer_url: String,
    /// The block time.
    pub created_at: DateTime<Utc>,
    /// `sent` or `received`.
    pub direction: String,
}

/// The wallet whose history is read.
pub struct WalletRef<'a> {
    pub wallet_id: &'a str,
    pub address: &'a str,
}

/// One page of history, newest first.
#[derive(Clone)]
pub struct HistoryPage {
    pub items: Vec<WalletTransaction>,
    /// The page's last signature, when the page is full.
    pub next_cursor: Option<String>,
}

struct CachedPage {
    page: HistoryPage,
    at: Instant,
}

/// Per-worker caches of history pages and parsed transactions.
pub struct History {
    pages: Mutex<LruCache<String, CachedPage>>,
    page_ttl: Duration,
    transactions: Mutex<LruCache<String, Arc<TransactionDetail>>>,
}

fn capacity(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).expect("cache capacity must be > 0")
}

fn page_key(address: &str, cursor: Option<&str>, limit: usize) -> String {
    format!("{address}|{}|{limit}", cursor.unwrap_or(""))
}

impl History {
    pub fn new(page_capacity: usize, page_ttl: Duration, transaction_capacity: usize) -> Self {
        Self {
            pages: Mutex::new(LruCache::new(capacity(page_capacity))),
            page_ttl,
            transactions: Mutex::new(LruCache::new(capacity(transaction_capacity))),
        }
    }

    /// One page of the wallet's history, starting after `cursor`.
    pub async fn page(
        &self,
        solana: &SolanaClient,
        wallet: &WalletRef<'_>,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<HistoryPage, ApiError> {
        if let Some(cursor) = cursor {
            Signature::from_str(cursor).map_err(|_| {
                ApiError::bad_request("invalid pagination cursor").with_code("invalid_cursor")
            })?;
        }
        let key = page_key(wallet.address, cursor, limit);
        if let Some(hit) = self.cached_page(&key) {
            return Ok(hit);
        }

        let address = Pubkey::from_str(wallet.address)
            .map_err(|_| ApiError::internal("stored wallet address is invalid"))?;
        let signatures = solana
            .rpc()
            .get_signatures_for_address(&address, cursor, None, Some(limit), "confirmed")
            .await
            .map_err(|e| ApiError::rpc_unavailable(format!("Solana RPC error: {e}")))?;
        let wanted: Vec<String> = signatures.iter().map(|s| s.signature.clone()).collect();
        let details: Vec<Arc<TransactionDetail>> = stream::iter(wanted)
            .map(|signature| async move { self.detail(solana, &signature).await })
            .buffered(FETCH_CONCURRENCY)
            .try_collect()
            .await?;

        let items = signatures
            .iter()
            .zip(&details)
            .map(|(info, detail)| {
                let mut tx = view(solana, wallet, &info.signature, detail);
                if let Some(at) = info.block_time.and_then(|t| DateTime::from_timestamp(t, 0)) {
                    tx.created_at = at;
                }
                tx
            })
            .collect();
        let page = HistoryPage {
            items,
            next_cursor: (signatures.len() == limit)
                .then(|| signatures.last().map(|s| s.signature.clone()))
                .flatten(),
        };
        if let Ok(mut pages) = self.pages.lock() {
            pages.put(
                key,
                CachedPage {
                    page: page.clone(),
                    at: Instant::now(),
                },
            );
        }
        Ok(page)
    }

    /// One transaction, if it touches the wallet.
    pub async fn transaction(
        &self,
        solana: &SolanaClient,
        wallet: &WalletRef<'_>,
        signature: &str,
    ) -> Result<Option<WalletTransaction>, ApiError> {
        if Signature::from_str(signature).is_err() {
            return Ok(None);
        }
        let detail = match self.detail(solana, signature).await {
            Ok(detail) => detail,
            Err(e) if e.code == "not_found" => return Ok(None),
            Err(e) => return Err(e),
        };
        let involved = detail
            .transaction
            .account_keys
            .iter()
            .any(|k| k == wallet.address)
            || detail.meta.as_ref().is_some_and(|m| {
                m.pre_token_balances
                    .iter()
                    .chain(&m.post_token_balances)
                    .any(|b| b.owner.as_deref() == Some(wallet.address))
            });
        Ok(involved.then(|| view(solana, wallet, signature, &detail)))
    }

    /// Drop the cached pages of an address whose history just changed.
    pub fn invalidate(&self, address: &str) {
        if let Ok(mut pages) = self.pages.lock() {
            let prefix = format!("{address}|");
            let stale: Vec<String> = pages
                .iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(k, _)| k.clone())
                .collect();
            for key in stale {
                pages.pop(&key);
            }
        }
    }

    fn cached_page(&self, key: &str) -> Option<HistoryPage> {
        let mut pages = self.pages.lock().ok()?;
        let hit = pages.get(key)?;
        if hit.at.elapsed() > self.page_ttl {
            pages.pop(key);
            return None;
        }
        Some(hit.page.clone())
    }

    async fn detail(
        &self,
        solana: &SolanaClient,
        signature: &str,
    ) -> Result<Arc<TransactionDetail>, ApiError> {
        if let Some(hit) = self
            .transactions
            .lock()
            .ok()
            .and_then(|mut c| c.get(signature).cloned())
        {
            return Ok(hit);
        }
        let detail = solana
            .rpc()
            .get_transaction(signature, "confirmed")
            .await
            .map_err(|e| {
                if e.message.contains("not found") {
                    ApiError::not_found(format!("transaction {signature} not found"))
                } else {
                    ApiError::rpc_unavailable(format!("Solana RPC error: {e}"))
                }
            })?;
        let detail = Arc::new(detail);
        if let Ok(mut cache) = self.transactions.lock() {
            cache.put(signature.to_string(), detail.clone());
        }
        Ok(detail)
    }
}

/// A transaction as the wallet sees it.
fn view(
    solana: &SolanaClient,
    wallet: &WalletRef<'_>,
    signature: &str,
    detail: &TransactionDetail,
) -> WalletTransaction {
    let side =
        token_side(detail, wallet.address).unwrap_or_else(|| sol_side(detail, wallet.address));
    let failed = detail.meta.as_ref().is_some_and(|m| m.err.is_some());
    WalletTransaction {
        signature: signature.to_string(),
        wallet_id: wallet.wallet_id.to_string(),
        from: side.from,
        to: side.to,
        amount: side.amount,
        amount_lamports: side.amount_lamports,
        token: side.token,
        network: solana.network().name.to_string(),
        status: if failed {
            TxStatus::Failed
        } else {
            TxStatus::Confirmed
        },
        slot: detail.slot,
        fee_lamports: detail.meta.as_ref().map_or(0, |m| m.fee),
        explorer_url: solana.network().explorer_tx_url(signature),
        created_at: detail
            .block_time
            .and_then(|t| DateTime::from_timestamp(t, 0))
            .unwrap_or_default(),
        direction: side.direction.to_string(),
    }
}

/// What a transaction moved, from one address's side.
struct Side {
    from: String,
    to: String,
    amount: String,
    amount_lamports: Option<u64>,
    token: TokenType,
    direction: &'static str,
}

/// A SOL transfer, from the address's balance change. The fee payer is the
/// sender, and the fee isn't part of the amount.
fn sol_side(detail: &TransactionDetail, address: &str) -> Side {
    let keys = &detail.transaction.account_keys;
    let fee_payer = keys.first().cloned().unwrap_or_default();
    let is_sender = fee_payer == address;
    let lamports = detail.meta.as_ref().and_then(|m| {
        let i = keys.iter().position(|k| k == address)?;
        let (pre, post) = (*m.pre_balances.get(i)?, *m.post_balances.get(i)?);
        Some(if is_sender {
            pre.saturating_sub(post).saturating_sub(m.fee)
        } else {
            post.saturating_sub(pre)
        })
    });
    let (from, to) = if is_sender {
        (
            address.to_string(),
            keys.get(1).cloned().unwrap_or_default(),
        )
    } else {
        (fee_payer, address.to_string())
    };
    Side {
        from,
        to,
        amount: lamports.map_or_else(|| "0".to_string(), |l| decimal(u128::from(l), 9)),
        amount_lamports: lamports,
        token: TokenType::Native,
        direction: if is_sender { "sent" } else { "received" },
    }
}

/// An SPL transfer, if the address's token balance for some mint changed.
/// The counterparty is the other owner whose balance of that mint moved the
/// other way.
fn token_side(detail: &TransactionDetail, address: &str) -> Option<Side> {
    let meta = detail.meta.as_ref()?;
    let change = |owner: &str, mint: &str| -> i128 {
        let sum = |entries: &[crate::blockchain::rpc::TokenBalanceEntry]| -> i128 {
            entries
                .iter()
                .filter(|b| b.owner.as_deref() == Some(owner) && b.mint == mint)
                .map(|b| i128::try_from(b.amount).unwrap_or(i128::MAX))
                .sum()
        };
        sum(&meta.post_token_balances) - sum(&meta.pre_token_balances)
    };
    let entry = meta
        .pre_token_balances
        .iter()
        .chain(&meta.post_token_balances)
        .find(|b| b.owner.as_deref() == Some(address) && change(address, &b.mint) != 0)?;
    let delta = change(address, &entry.mint);
    let counterparty = meta
        .pre_token_balances
        .iter()
        .chain(&meta.post_token_balances)
        .filter_map(|b| {
            b.owner
                .as_deref()
                .filter(|o| *o != address && b.mint == entry.mint)
        })
        .find(|o| change(o, &entry.mint).signum() == -delta.signum())
        .unwrap_or_default()
        .to_string();
    let (from, to, direction) = if delta < 0 {
        (address.to_string(), counterparty, "sent")
    } else {
        (counterparty, address.to_string(), "received")
    };
    Some(Side {
        from,
        to,
        amount: decimal(delta.unsigned_abs(), entry.decimals),
        amount_lamports: None,
        token: TokenType::SplToken(entry.mint.clone()),
        direction,
    })
}

/// `raw` smallest units as a decimal with `decimals` places.
fn decimal(raw: u128, decimals: u8) -> String {
    if decimals == 0 {
        return raw.to_string();
    }
    let scale = 10u128.pow(u32::from(decimals));
    format!(
        "{}.{:0width$}",
        raw / scale,
        raw % scale,
        width = usize::from(decimals)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::rpc::parse_transaction;
    use crate::blockchain::types::devnet_config;

    const ALICE: &str = "Alice111111111111111111111111111111111111111";
    const BOB: &str = "Bob11111111111111111111111111111111111111111";
    const MINT: &str = "Mint1111111111111111111111111111111111111111";

    fn solana() -> SolanaClient {
        SolanaClient::new("http://127.0.0.1:9", devnet_config("http://127.0.0.1:9"))
    }

    fn alice() -> WalletRef<'static> {
        WalletRef {
            wallet_id: "w-alice",
            address: ALICE,
        }
    }

    fn bob() -> WalletRef<'static> {
        WalletRef {
            wallet_id: "w-bob",
            address: BOB,
        }
    }

    /// Alice pays Bob 1.5 SOL with a 5,000-lamport fee.
    fn sol_transfer() -> TransactionDetail {
        parse_transaction(&serde_json::json!({
            "slot": 7,
            "blockTime": 1_700_000_000,
            "meta": {
                "err": null,
                "fee": 5000,
                "preBalances": [3_000_005_000u64, 1_000_000_000u64, 1],
                "postBalances": [1_500_000_000u64, 2_500_000_000u64, 1],
                "logMessages": [],
            },
            "transaction": { "message": { "accountKeys": [
                { "pubkey": ALICE }, { "pubkey": BOB }, { "pubkey": "11111111111111111111111111111111" }
            ] } },
        }))
    }

    #[test]
    fn sol_transfers_read_from_balance_changes_on_both_sides() {
        let (solana, detail) = (solana(), sol_transfer());
        let sent = view(&solana, &alice(), "sig1", &detail);
        assert_eq!(
            (
                sent.direction.as_str(),
                sent.from.as_str(),
                sent.to.as_str()
            ),
            ("sent", ALICE, BOB)
        );
        assert_eq!(sent.amount, "1.500000000");
        assert_eq!(sent.amount_lamports, Some(1_500_000_000));
        assert_eq!((sent.fee_lamports, sent.slot), (5000, 7));
        assert_eq!(sent.status, TxStatus::Confirmed);
        assert_eq!(sent.created_at.timestamp(), 1_700_000_000);

        let received = view(&solana, &bob(), "sig1", &detail);
        assert_eq!(
            (received.direction.as_str(), received.from.as_str()),
            ("received", ALICE)
        );
        assert_eq!(received.amount_lamports, Some(1_500_000_000));
        assert_eq!(received.wallet_id, "w-bob");
    }

    #[test]
    fn spl_transfers_read_from_token_balance_changes() {
        let balance = |index: u64, owner: &str, amount: &str| {
            serde_json::json!({
                "accountIndex": index, "mint": MINT, "owner": owner,
                "uiTokenAmount": { "amount": amount, "decimals": 6 }
            })
        };
        let detail = parse_transaction(&serde_json::json!({
            "slot": 9,
            "meta": {
                "err": { "InstructionError": [0, "Custom"] },
                "fee": 5000,
                "preBalances": [10_000, 1, 1], "postBalances": [5_000, 1, 1],
                "preTokenBalances": [balance(1, ALICE, "2500000"), balance(2, BOB, "0")],
                "postTokenBalances": [balance(1, ALICE, "500000"), balance(2, BOB, "2000000")],
            },
            "transaction": { "message": { "accountKeys": [ALICE, "AliceAta", "BobAta"] } },
        }));
        let solana = solana();
        let sent = view(&solana, &alice(), "sig2", &detail);
        assert_eq!(sent.token, TokenType::SplToken(MINT.into()));
        assert_eq!(
            (
                sent.amount.as_str(),
                sent.direction.as_str(),
                sent.to.as_str()
            ),
            ("2.000000", "sent", BOB)
        );
        assert_eq!(sent.amount_lamports, None);
        assert_eq!(sent.status, TxStatus::Failed);

        let received = view(&solana, &bob(), "sig2", &detail);
        assert_eq!(
            (received.direction.as_str(), received.from.as_str()),
            ("received", ALICE)
        );
    }

    #[test]
    fn decimals_are_exact() {
        assert_eq!(decimal(1, 9), "0.000000001");
        assert_eq!(decimal(12_345, 0), "12345");
        assert_eq!(decimal(u128::from(u64::MAX), 9), "18446744073.709551615");
    }

    #[tokio::test]
    async fn pages_are_cached_per_address_until_invalidated() {
        let history = History::new(8, Duration::from_secs(30), 8);
        let page = HistoryPage {
            items: Vec::new(),
            next_cursor: Some("sig".into()),
        };
        for (address, cursor) in [(ALICE, None), (ALICE, Some("x")), (BOB, None)] {
            history.pages.lock().unwrap().put(
                page_key(address, cursor, 20),
                CachedPage {
                    page: page.clone(),
                    at: Instant::now(),
                },
            );
        }
        history.invalidate(ALICE);
        assert!(history.cached_page(&page_key(ALICE, None, 20)).is_none());
        assert!(history
            .cached_page(&page_key(ALICE, Some("x"), 20))
            .is_none());
        assert!(history.cached_page(&page_key(BOB, None, 20)).is_some());

        // A cursor that isn't a signature is refused before any RPC call.
        let err = history
            .page(&solana(), &alice(), Some("not-a-signature"), 20)
            .await
            .err()
            .unwrap();
        assert_eq!(err.code, "invalid_cursor");
    }
}
