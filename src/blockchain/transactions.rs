// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Transfers, their receipts, fee estimates and confirmation.
//!
//! A transfer also creates a receipt: an account with no data, owned by the
//! System program, at an address derived from the wallet and a seed that
//! names the request. Creating an account fails where one exists, so a
//! second copy of the transfer can never succeed, and a retry learns
//! whether the transfer happened from whether its receipt exists, with no
//! need for the RPC's history. The deposit goes back to the wallet once
//! retries of the request are no longer accepted.

use solana_instruction::Instruction;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_system_interface::instruction as system_instruction;

use super::client::SolanaClient;
use super::rpc::{Account, SignatureStatus};
use super::spl_token::system_program_id;
use crate::error::ApiError;

/// The receipt address of the transfer from `wallet` that `seed` names.
pub fn receipt_address(wallet: &Pubkey, seed: &str) -> Result<Pubkey, ApiError> {
    Pubkey::create_with_seed(wallet, seed, system_program_id())
        .map_err(|e| ApiError::internal(format!("deriving a receipt address: {e}")))
}

/// The instruction that creates the receipt at `receipt`, holding
/// `deposit` lamports from `wallet`.
pub fn create_receipt(wallet: &Pubkey, receipt: &Pubkey, seed: &str, deposit: u64) -> Instruction {
    system_instruction::create_account_with_seed(
        wallet,
        receipt,
        wallet,
        seed,
        deposit,
        0,
        system_program_id(),
    )
}

/// The instruction that returns all `lamports` of the receipt at `receipt`
/// to `wallet`, which removes it.
pub fn sweep_receipt(wallet: &Pubkey, receipt: &Pubkey, seed: &str, lamports: u64) -> Instruction {
    system_instruction::transfer_with_seed(
        receipt,
        wallet,
        seed.to_string(),
        system_program_id(),
        wallet,
        lamports,
    )
}

/// Whether `account` is a receipt: an account with no data that the System
/// program owns. Lamports sent to the address make one too, which a
/// transfer's own outcome tells apart.
pub fn is_receipt(account: Option<&Account>) -> bool {
    account.is_some_and(|a| &a.owner == system_program_id() && a.data.is_empty())
}

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

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use serde_json::json;
    use solana_transaction::Transaction;

    use super::*;
    use crate::blockchain::drt::accounts::fetch_pool;
    use crate::blockchain::rpc::JsonRpcClient;
    use crate::config::DEFAULT_SOLANA_RPC_URL;

    /// A devnet pool whose owner's wallet holds SOL; `GRANT_GUARD_POOL`
    /// names another.
    const DEVNET_POOL: &str = "3QhZF66CnE8prTFYwoETNuLdtya2mB8CtnJZ4EsML7XH";

    #[test]
    fn a_receipt_is_the_wallets_seeded_address_under_the_system_program() {
        let wallet = Pubkey::new_from_array([7; 32]);
        let seed = "133dfaefa5935294a19687842fc22601";
        let receipt = receipt_address(&wallet, seed).unwrap();
        assert_eq!(
            receipt,
            Pubkey::create_with_seed(&wallet, seed, system_program_id()).unwrap()
        );
        let create = create_receipt(&wallet, &receipt, seed, 890_880);
        assert_eq!(create.program_id, *system_program_id());
        assert_eq!(create.accounts[1].pubkey, receipt);
        let sweep = sweep_receipt(&wallet, &receipt, seed, 890_880);
        assert_eq!(
            sweep.accounts.iter().map(|a| a.pubkey).collect::<Vec<_>>(),
            [receipt, wallet, wallet]
        );
        assert!(receipt_address(&wallet, &"x".repeat(33)).is_err());
    }

    /// On devnet: a transaction that creates a receipt passes, and one that
    /// creates the same receipt twice fails at the second with the System
    /// program's "already in use" (error 0), which the worker reads as the
    /// receipt being taken. Simulated without signature checks, paid by the
    /// owner of `GRANT_GUARD_POOL`, so it needs no keys and spends nothing.
    #[tokio::test]
    #[ignore = "calls devnet: run with `just grant-guard`"]
    async fn devnet_refuses_a_second_transfer_receipt() {
        let url = std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| DEFAULT_SOLANA_RPC_URL.into());
        let rpc = JsonRpcClient::new(&url, "confirmed");
        let pool: Pubkey = std::env::var("GRANT_GUARD_POOL")
            .unwrap_or_else(|_| DEVNET_POOL.into())
            .parse()
            .unwrap();
        let wallet = fetch_pool(&rpc, &pool).await.unwrap().owner;
        let deposit = rpc.get_minimum_balance_for_rent_exemption(0).await.unwrap();
        let seed = uuid::Uuid::new_v4().simple().to_string();
        let receipt = receipt_address(&wallet, &seed).unwrap();
        let simulate = |instructions: Vec<Instruction>| {
            let tx = Transaction::new_unsigned(Message::new(&instructions, Some(&wallet)));
            let encoded = BASE64.encode(bincode::serialize(&tx).unwrap());
            let rpc = &rpc;
            async move { rpc.simulate_transaction(&encoded).await.unwrap() }
        };

        let create = create_receipt(&wallet, &receipt, &seed, deposit);
        let (failed, logs) = simulate(vec![create.clone()]).await;
        assert!(
            failed.is_none(),
            "creating a receipt failed: {failed:?} {logs:#?}"
        );
        let (failed, logs) = simulate(vec![create.clone(), create]).await;
        assert_eq!(
            failed,
            Some(json!({ "InstructionError": [1, { "Custom": 0 }] })),
            "{logs:#?}"
        );
        eprintln!("devnet: a receipt under {wallet} is created once and refused the second time");
    }

    /// On the real System program, with its transfer: a receipt is made
    /// once, a second copy of the transfer is refused before it runs with
    /// "already in use" at the receipt, and a sweep returns the deposit and
    /// leaves nothing there.
    #[tokio::test]
    #[ignore = "needs a surfnet: run `just chain-test`"]
    async fn surfnet_makes_a_receipt_once_and_sweeps_it() {
        use crate::blockchain::surfnet;
        use solana_keypair::Keypair;
        use solana_signer::Signer;

        let solana = surfnet::client();
        let keypair = Keypair::new();
        let wallet = keypair.pubkey();
        surfnet::fund(&wallet, 2_000_000_000).await;
        let rpc = solana.rpc();
        let deposit = rpc.get_minimum_balance_for_rent_exemption(0).await.unwrap();
        let seed = uuid::Uuid::new_v4().simple().to_string();
        let receipt = receipt_address(&wallet, &seed).unwrap();
        let send = |instructions: Vec<Instruction>| {
            let (keypair, solana) = (&keypair, &solana);
            async move {
                let (blockhash, _) = solana.rpc().get_latest_blockhash().await.unwrap();
                let tx = crate::api::pools::signed(keypair, &instructions)(blockhash);
                let encoded = BASE64.encode(bincode::serialize(&tx).unwrap());
                solana.rpc().send_encoded_transaction(&encoded).await?;
                let signature = tx.signatures[0].to_string();
                solana
                    .await_confirmation(&signature, "confirmed")
                    .await
                    .unwrap();
                Ok::<_, crate::blockchain::rpc::RpcError>(signature)
            }
        };

        let mut transfer = vec![create_receipt(&wallet, &receipt, &seed, deposit)];
        transfer.extend(native_transfer(&wallet, &Pubkey::new_unique(), 1_000_000));
        send(transfer.clone()).await.unwrap();
        let made = rpc.get_account(&receipt, "confirmed").await.unwrap();
        assert!(is_receipt(made.as_ref()), "the transfer makes its receipt");

        let refused = send(transfer).await.unwrap_err();
        assert_eq!(
            refused.rejection(),
            Some(&json!({ "InstructionError": [0, { "Custom": 0 }] })),
            "{refused}"
        );

        send(vec![sweep_receipt(&wallet, &receipt, &seed, deposit)])
            .await
            .unwrap();
        assert!(rpc
            .get_account(&receipt, "confirmed")
            .await
            .unwrap()
            .is_none());
    }
}
