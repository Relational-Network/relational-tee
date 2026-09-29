// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Build, sign, and send Solana transactions (native SOL + SPL tokens).

use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_system_interface::instruction as system_instruction;
use solana_transaction::Transaction;
use std::str::FromStr;
use tracing::info;

use super::client::SolanaClient;
use super::types::SendResult;
use crate::error::ApiError;

impl SolanaClient {
    /// Poll the RPC until the given signature reaches the requested commitment level.
    ///
    /// - `confirmed` (~400ms-2s): single validator confirmation.
    /// - `finalized` (~15-30s): 32 confirmations.
    ///
    /// Timeout and poll interval adjust automatically based on the commitment.
    pub async fn await_confirmation(
        &self,
        signature: &Signature,
        commitment: &str,
    ) -> Result<(), ApiError> {
        let (timeout, poll_interval) = if commitment == "finalized" {
            (
                std::time::Duration::from_secs(60),
                std::time::Duration::from_millis(1000),
            )
        } else {
            (
                std::time::Duration::from_secs(30),
                std::time::Duration::from_millis(400),
            )
        };
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > timeout {
                return Err(ApiError::service_unavailable(format!(
                    "transaction confirmation timed out ({timeout:?}) at {commitment}"
                )));
            }
            match self.rpc.get_signature_statuses(&[signature]).await {
                Ok(statuses) => {
                    if let Some(Some(status)) = statuses.first() {
                        if status.err.is_some() {
                            return Err(ApiError::service_unavailable(
                                "transaction failed on-chain",
                            ));
                        }
                        let confirmed = match status.confirmation_status.as_deref() {
                            Some("finalized") => true,
                            Some("confirmed") => commitment != "finalized",
                            _ => false,
                        };
                        if confirmed {
                            return Ok(());
                        }
                    }
                    tokio::time::sleep(poll_interval).await;
                }
                Err(_) => tokio::time::sleep(poll_interval).await,
            }
        }
    }

    /// Send native SOL from `keypair` to `recipient`.
    pub async fn send_native(
        &self,
        keypair: &Keypair,
        recipient: &str,
        lamports: u64,
    ) -> Result<SendResult, ApiError> {
        let to = Pubkey::from_str(recipient)
            .map_err(|_| ApiError::unprocessable(format!("invalid recipient: {recipient}")))?;

        let instruction = system_instruction::transfer(&keypair.pubkey(), &to, lamports);
        let recent_blockhash =
            self.rpc.get_latest_blockhash().await.map_err(|e| {
                ApiError::service_unavailable(format!("blockhash fetch failed: {e}"))
            })?;

        let message = Message::new(&[instruction], Some(&keypair.pubkey()));
        let tx = Transaction::new(&[keypair], message, recent_blockhash);

        let signature: Signature =
            self.rpc.send_transaction(&tx).await.map_err(|e| {
                ApiError::service_unavailable(format!("transaction send failed: {e}"))
            })?;

        self.await_confirmation(&signature, "confirmed").await?;

        let sig_str = signature.to_string();
        info!(signature = %sig_str, to = %recipient, lamports, "SOL transfer sent");

        Ok(SendResult {
            explorer_url: self.network.explorer_tx_url(&sig_str),
            signature: sig_str,
        })
    }

    /// Estimate the fee for a transfer message.
    pub async fn estimate_fee(
        &self,
        from: &Pubkey,
        to: &Pubkey,
        lamports: u64,
    ) -> Result<u64, ApiError> {
        let instruction = system_instruction::transfer(from, to, lamports);
        let recent_blockhash =
            self.rpc.get_latest_blockhash().await.map_err(|e| {
                ApiError::service_unavailable(format!("blockhash fetch failed: {e}"))
            })?;

        let message = Message::new_with_blockhash(&[instruction], Some(from), &recent_blockhash);
        self.rpc
            .get_fee_for_message(&message)
            .await
            .map_err(|e| ApiError::service_unavailable(format!("fee estimation failed: {e}")))
    }
}
