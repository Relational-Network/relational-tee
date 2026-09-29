// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Fetches new Solana transaction signatures for our wallets' addresses and
//! stores them in each wallet's history.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use solana_pubkey::Pubkey;
use std::str::FromStr;
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::blockchain::SolanaClient;
use crate::storage::transactions::{StoredTransaction, TokenType, TxStatus};
use crate::storage::tx_cache::TxCache;
use crate::storage::Storage;

type PollError = Box<dyn std::error::Error + Send + Sync>;

/// Start the background indexer.
///
/// This spawns a Tokio task that runs forever (until the runtime shuts down).
/// Call from `main` after building `AppState`.
pub fn spawn_indexer(
    solana: Arc<SolanaClient>,
    storage: Arc<Storage>,
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
            if let Err(e) = poll_once(&solana, &storage, &tx_cache).await {
                warn!(error = %e, "Indexer poll cycle failed");
            }
        }
    });
}

/// Sync one address on demand, unless any worker synced it within the
/// cooldown (`SYNC_COOLDOWN_SECS`), which stops repeated RPC calls on rapid
/// page loads.
pub async fn sync_address_once(
    solana: &SolanaClient,
    storage: &Storage,
    tx_cache: &Arc<TxCache>,
    address: &str,
    wallet_id: &str,
) -> Result<(), PollError> {
    let cooldown = chrono::Duration::seconds(crate::config::SYNC_COOLDOWN_SECS as i64);
    let Some(claim) = storage.transactions().claim_sync(address, cooldown).await? else {
        debug!(address = %address, "Sync cooldown active — skipping RPC call");
        return Ok(());
    };
    let until = claim.until.clone();
    let newest = poll_address(solana, storage, address, wallet_id, until.as_deref()).await?;
    storage.transactions().finish_sync(claim, newest).await?;
    tx_cache.invalidate(wallet_id);
    Ok(())
}

/// Single poll cycle: iterate all registered addresses and fetch new sigs.
async fn poll_once(
    solana: &SolanaClient,
    storage: &Storage,
    tx_cache: &Arc<TxCache>,
) -> Result<(), PollError> {
    let addresses = storage.wallets().addresses().await?;
    debug!(address_count = addresses.len(), "Indexer polling addresses");

    for (address, wallet_id) in &addresses {
        if let Err(e) = sync_address_once(solana, storage, tx_cache, address, wallet_id).await {
            warn!(address = %address, error = %e, "Failed to poll address");
        }
    }

    Ok(())
}

/// Fetch signatures newer than `until` for one address and store the
/// transactions. Returns the newest signature seen.
async fn poll_address(
    solana: &SolanaClient,
    storage: &Storage,
    address: &str,
    wallet_id: &str,
    until: Option<&str>,
) -> Result<Option<String>, PollError> {
    let pubkey = Pubkey::from_str(address)?;

    // Fetch recent signatures via JSON-RPC.
    let sigs = solana
        .rpc()
        .get_signatures_for_address(&pubkey, None, until, Some(50), "confirmed")
        .await?;

    if sigs.is_empty() {
        return Ok(None);
    }

    debug!(
        address = %address,
        new_sigs = sigs.len(),
        "Indexer found new signatures"
    );

    // The first signature in the list is the most recent.
    let newest_sig = sigs.first().map(|s| s.signature.clone());

    for sig_info in &sigs {
        let sig_str = &sig_info.signature;

        // Skip if we already have this tx.
        if storage
            .transactions()
            .get(wallet_id, sig_str)
            .await?
            .is_some()
        {
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
                let counterparty_wallet_id = storage
                    .wallets()
                    .wallet_id_for_address(counterparty_addr)
                    .await
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
                if let Err(e) = storage
                    .transactions()
                    .upsert(wallet_id, &stored, direction)
                    .await
                {
                    warn!(sig = %sig_str, error = %e, "Failed to store indexed tx");
                }
            }
            Err(e) => {
                debug!(sig = %sig_str, error = %e, "Failed to fetch tx detail (skipping)");
            }
        }
    }

    Ok(newest_sig)
}
