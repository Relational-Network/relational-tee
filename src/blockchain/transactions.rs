// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Transfers, fee estimates and confirmation.

use solana_instruction::Instruction;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_system_interface::instruction as system_instruction;

use super::client::SolanaClient;
use super::rpc::SignatureStatus;
use crate::error::ApiError;

/// Whether `status` has reached `commitment` (`confirmed` or `finalized`).
pub fn reached(status: &SignatureStatus, commitment: &str) -> bool {
    match status.confirmation_status.as_deref() {
        Some("finalized") => true,
        Some("confirmed") => commitment != "finalized",
        _ => false,
    }
}

/// The instruction for a native SOL transfer.
pub fn native_transfer(from: &Pubkey, to: &Pubkey, lamports: u64) -> Vec<Instruction> {
    vec![system_instruction::transfer(from, to, lamports)]
}

impl SolanaClient {
    /// Poll until the transaction reaches `commitment`:
    ///
    /// - `confirmed` (~400ms-2s): single validator confirmation.
    /// - `finalized` (~15-30s): 32 confirmations.
    ///
    /// Fails if the transaction failed on-chain or the wait times out.
    pub async fn await_confirmation(
        &self,
        signature: &str,
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
                return Err(ApiError::rpc_unavailable(format!(
                    "transaction confirmation timed out ({timeout:?}) at {commitment}"
                )));
            }
            if let Ok(Some(status)) = self.rpc.signature_status(signature).await {
                if status.err.is_some() {
                    return Err(ApiError::rpc_unavailable("transaction failed on-chain"));
                }
                if reached(&status, commitment) {
                    return Ok(());
                }
            }
            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Estimate the fee for a transfer message.
    pub async fn estimate_fee(
        &self,
        from: &Pubkey,
        to: &Pubkey,
        lamports: u64,
    ) -> Result<u64, ApiError> {
        let (recent_blockhash, _) = self
            .rpc
            .get_latest_blockhash()
            .await
            .map_err(|e| ApiError::rpc_unavailable(format!("blockhash fetch failed: {e}")))?;
        let message = Message::new_with_blockhash(
            &native_transfer(from, to, lamports),
            Some(from),
            &recent_blockhash,
        );
        self.rpc
            .get_fee_for_message(&message)
            .await
            .map_err(|e| ApiError::rpc_unavailable(format!("fee estimation failed: {e}")))
    }
}
