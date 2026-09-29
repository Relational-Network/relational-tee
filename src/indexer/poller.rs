// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Polling loop that fetches new Solana transaction signatures for watched
//! addresses and upserts them into the [`TxDatabase`].

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use solana_pubkey::Pubkey;
use std::str::FromStr;
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::blockchain::SolanaClient;
use crate::storage::repository::transactions::{StoredTransaction, TokenType, TxStatus};
use crate::storage::tx_cache::TxCache;
use crate::storage::tx_database::TxDatabase;

/// Start the background indexer.
///
/// This spawns a Tokio task that runs forever (until the runtime shuts down).
/// Call from `main` after building `AppState`.
pub fn spawn_indexer(
    solana: Arc<SolanaClient>,
    tx_db: Arc<TxDatabase>,
    tx_cache: Arc<TxCache>,
    poll_interval: Duration,
) {
    tokio::spawn(async move {
        info!(
            interval_secs = poll_interval.as_secs(),
            "Transaction indexer started"
        );
        let mut ticker = interval(poll_interval);

        loop {
            ticker.tick().await;
            if let Err(e) = poll_once(&solana, &tx_db, &tx_cache).await {
                warn!(error = %e, "Indexer poll cycle failed");
            }
        }
    });
}

/// Trigger a one-shot sync for a single address.
///
/// Respects a per-address cooldown (`SYNC_COOLDOWN_SECS`) to prevent
/// expensive repeated RPC calls on rapid page loads.
pub async fn sync_address_once(
    solana: &SolanaClient,
    tx_db: &TxDatabase,
    tx_cache: &Arc<TxCache>,
    address: &str,
    wallet_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Check sync cooldown.
    let cooldown_key = format!("last_sync_ts:{address}");
    if let Ok(Some(ts_bytes)) = tx_db.get_indexer_state(&cooldown_key) {
        if let Ok(ts_str) = std::str::from_utf8(&ts_bytes) {
            if let Ok(last_ts) = ts_str.parse::<i64>() {
                let now = Utc::now().timestamp();
                if now - last_ts < crate::config::SYNC_COOLDOWN_SECS as i64 {
                    debug!(address = %address, "Sync cooldown active — skipping RPC call");
                    return Ok(());
                }
            }
        }
    }

    poll_address(solana, tx_db, tx_cache, address, wallet_id).await?;

    // Update cooldown timestamp.
    let now_str = Utc::now().timestamp().to_string();
    tx_db.set_indexer_state(&cooldown_key, now_str.as_bytes())?;

    Ok(())
}

/// Single poll cycle: iterate all registered addresses and fetch new sigs.
async fn poll_once(
    solana: &SolanaClient,
    tx_db: &TxDatabase,
    tx_cache: &Arc<TxCache>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addresses = tx_db.get_all_addresses()?;
    debug!(address_count = addresses.len(), "Indexer polling addresses");

    for (address, wallet_id) in &addresses {
        if let Err(e) = poll_address(solana, tx_db, tx_cache, address, wallet_id).await {
            warn!(address = %address, error = %e, "Failed to poll address");
        }
    }

    Ok(())
}

/// Poll a single address for new transaction signatures.
async fn poll_address(
    solana: &SolanaClient,
    tx_db: &TxDatabase,
    tx_cache: &Arc<TxCache>,
    address: &str,
    wallet_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let pubkey = Pubkey::from_str(address)?;

    // Get last-seen signature for this address (to avoid re-fetching).
    let state_key = format!("last_sig:{address}");
    let last_sig = tx_db.get_indexer_state(&state_key)?;
    let until_sig = last_sig
        .as_deref()
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(String::from);

    // Fetch recent signatures via JSON-RPC.
    let sigs = solana
        .rpc()
        .get_signatures_for_address(&pubkey, None, until_sig.as_deref(), Some(50), "confirmed")
        .await?;

    if sigs.is_empty() {
        return Ok(());
    }

    debug!(
        address = %address,
        new_sigs = sigs.len(),
        "Indexer found new signatures"
    );

    let mut newest_sig: Option<String> = None;

    for sig_info in &sigs {
        let sig_str = &sig_info.signature;

        // Track the newest signature (first in the list = most recent).
        if newest_sig.is_none() {
            newest_sig = Some(sig_str.clone());
        }

        // Skip if we already have this tx.
        if tx_db.get_transaction(sig_str)?.is_some() {
            continue;
        }

        // Fetch full transaction details via JSON-RPC.
        match solana.rpc().get_transaction(sig_str, "confirmed").await {
            Ok(tx_detail) => {
                let status = if sig_info.err.is_some() {
                    TxStatus::Failed
                } else {
                    TxStatus::Confirmed
                };

                let now = Utc::now();

                // Extract fee payer (first account key) to determine direction.
                let account_keys = &tx_detail.transaction.account_keys;
                let fee_payer = account_keys.first().cloned().unwrap_or_default();
                let is_sender = fee_payer == address;

                // ── Amount parsing from pre/post balances ──────────
                let fee = tx_detail.meta.as_ref().map(|m| m.fee).unwrap_or(0);
                let (amount_lamports, amount_display) = if let Some(meta) = &tx_detail.meta {
                    // Find the index of our address in the account keys.
                    let addr_index = account_keys.iter().position(|k| k == address);

                    if let Some(idx) = addr_index {
                        let pre = meta.pre_balances.get(idx).copied().unwrap_or(0);
                        let post = meta.post_balances.get(idx).copied().unwrap_or(0);
                        // For the sender, subtract the fee to get the actual transfer amount.
                        let lam = if is_sender {
                            pre.saturating_sub(post).saturating_sub(fee)
                        } else {
                            post.saturating_sub(pre)
                        };
                        let sol = lam as f64 / 1_000_000_000.0;
                        (Some(lam), format!("{sol:.9}"))
                    } else {
                        (None, "0".to_string())
                    }
                } else {
                    (None, "0".to_string())
                };

                // ── Counterparty resolution ─────────────────────
                // For sent txs: find the recipient (usually 2nd account key).
                // For received txs: fee payer is the sender.
                let (from_addr, to_addr) = if is_sender {
                    let recipient = account_keys.get(1).cloned().unwrap_or_default();
                    (address.to_string(), recipient)
                } else {
                    (fee_payer.clone(), address.to_string())
                };

                // Resolve counterparty wallet_id if the other address is registered.
                let counterparty_addr = if is_sender { &to_addr } else { &from_addr };
                let counterparty_wallet_id = tx_db
                    .get_wallet_id_for_address(counterparty_addr)
                    .ok()
                    .flatten();

                let stored = StoredTransaction {
                    signature: sig_str.clone(),
                    wallet_id: wallet_id.to_string(),
                    counterparty_wallet_id,
                    from: from_addr,
                    to: to_addr,
                    amount: amount_display,
                    amount_lamports,
                    token: TokenType::Native,
                    network: solana.network().name.to_string(),
                    status,
                    slot: Some(tx_detail.slot),
                    fee_lamports: tx_detail.meta.as_ref().map(|m| m.fee),
                    explorer_url: solana.network().explorer_tx_url(sig_str),
                    created_at: sig_info
                        .block_time
                        .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
                        .unwrap_or(now),
                    updated_at: now,
                };

                // Determine direction: if this address is the fee payer, it's "sent".
                let direction = if is_sender { "sent" } else { "received" };
                let directions = vec![(address.to_string(), direction)];

                if let Err(e) = tx_db.upsert_transaction(&stored, &directions) {
                    warn!(sig = %sig_str, error = %e, "Failed to store indexed tx");
                }
            }
            Err(e) => {
                debug!(sig = %sig_str, error = %e, "Failed to fetch tx detail (skipping)");
            }
        }
    }

    // Update the last-seen signature.
    if let Some(newest) = newest_sig {
        tx_db.set_indexer_state(&state_key, newest.as_bytes())?;
    }

    // Invalidate tx cache for this address so queries see fresh data.
    tx_cache.invalidate(address);

    Ok(())
}
