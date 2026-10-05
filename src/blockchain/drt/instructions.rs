// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Raw Solana instruction builders for the `digital_rights_tokens` program.
//!
//! Each function returns a `solana_instruction::Instruction` ready to be
//! included in a transaction. No `anchor-client` dependency — we build the
//! instruction data directly with the 8-byte Anchor discriminator followed by
//! Borsh-serialized arguments.

use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use std::str::FromStr;
use std::sync::OnceLock;

use super::pda::{derive_drt_config_pda, derive_grant_pda, derive_mint_pda, derive_user_ata};
use super::types::*;
use crate::config::drt_program_id;

// ============================================================================
// Helpers
// ============================================================================

fn system_program_id() -> Pubkey {
    static ID: OnceLock<Pubkey> = OnceLock::new();
    *ID.get_or_init(|| Pubkey::from_str(SYSTEM_PROGRAM_ID_STR).expect("valid system program ID"))
}

fn token_program_id() -> Pubkey {
    static ID: OnceLock<Pubkey> = OnceLock::new();
    *ID.get_or_init(|| Pubkey::from_str(TOKEN_PROGRAM_ID_STR).expect("valid SPL Token program ID"))
}

fn associated_token_program_id() -> Pubkey {
    static ID: OnceLock<Pubkey> = OnceLock::new();
    *ID.get_or_init(|| {
        Pubkey::from_str(ASSOCIATED_TOKEN_PROGRAM_ID_STR).expect("valid ATA program ID")
    })
}

fn rent_sysvar_id() -> Pubkey {
    static ID: OnceLock<Pubkey> = OnceLock::new();
    *ID.get_or_init(|| Pubkey::from_str(RENT_SYSVAR_ID_STR).expect("valid rent sysvar ID"))
}

/// Build a `ComputeBudgetProgram::SetComputeUnitLimit` instruction.
pub fn build_compute_budget_ix(units: u32) -> Instruction {
    static COMPUTE_BUDGET_ID: OnceLock<Pubkey> = OnceLock::new();
    let program_id = *COMPUTE_BUDGET_ID.get_or_init(|| {
        Pubkey::from_str("ComputeBudget111111111111111111111111111111")
            .expect("valid ComputeBudget program ID")
    });
    let mut data = vec![2u8]; // SetComputeUnitLimit
    data.extend_from_slice(&units.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![],
        data,
    }
}

// ============================================================================
// create_pool
// ============================================================================

/// Build the `create_pool` instruction.
///
/// Accounts (in IDL order): owner (writable, signer), pool (PDA, writable),
/// system_program.
pub fn build_create_pool(owner: &Pubkey, pool_pda: &Pubkey, pool_uuid: &[u8; 16]) -> Instruction {
    let mut data = Vec::with_capacity(8 + 16);
    data.extend_from_slice(&DISC_CREATE_POOL);
    data.extend_from_slice(pool_uuid);

    let accounts = vec![
        AccountMeta::new(*owner, true),
        AccountMeta::new(*pool_pda, false),
        AccountMeta::new_readonly(system_program_id(), false),
    ];

    Instruction {
        program_id: drt_program_id(),
        accounts,
        data,
    }
}

// ============================================================================
// register_drt
// ============================================================================

/// Build the `register_drt` instruction.
///
/// Accounts (in IDL order): owner (writable, signer), pool, drt_config
/// (writable), mint (writable), holder, holder_ata (writable), token_program,
/// associated_token_program, system_program, rent.
pub fn build_register_drt(
    owner: &Pubkey,
    pool_pda: &Pubkey,
    holder: &Pubkey,
    right_id: &[u8; 16],
    code_repo_url: &str,
    code_hash: &[u8; 32],
    supply: u64,
) -> Result<Instruction, String> {
    let (drt_config_pda, _) = derive_drt_config_pda(pool_pda, right_id);
    let (mint_pda, _) = derive_mint_pda(pool_pda, right_id);
    let holder_ata = derive_user_ata(holder, &mint_pda);

    let mut data = Vec::new();
    data.extend_from_slice(&DISC_REGISTER_DRT);
    data.extend_from_slice(right_id);
    code_repo_url
        .to_string()
        .serialize(&mut data)
        .map_err(|e| format!("Borsh serialize code_repo_url: {e}"))?;
    data.extend_from_slice(code_hash);
    data.extend_from_slice(&supply.to_le_bytes());

    let accounts = vec![
        AccountMeta::new(*owner, true),
        AccountMeta::new_readonly(*pool_pda, false),
        AccountMeta::new(drt_config_pda, false),
        AccountMeta::new(mint_pda, false),
        AccountMeta::new_readonly(*holder, false),
        AccountMeta::new(holder_ata, false),
        AccountMeta::new_readonly(token_program_id(), false),
        AccountMeta::new_readonly(associated_token_program_id(), false),
        AccountMeta::new_readonly(system_program_id(), false),
        AccountMeta::new_readonly(rent_sysvar_id(), false),
    ];

    Ok(Instruction {
        program_id: drt_program_id(),
        accounts,
        data,
    })
}

// ============================================================================
// grant_right
// ============================================================================

/// Build the `grant_right` instruction (burns 1 token + creates Grant PDA).
///
/// Accounts (in IDL order): pool, drt_config, mint (writable), holder
/// (writable, signer), holder_ata (writable), grant (writable, PDA from
/// commitment), token_program, system_program.
pub fn build_grant_right(
    pool_pda: &Pubkey,
    drt_config_pda: &Pubkey,
    mint: &Pubkey,
    holder: &Pubkey,
    commitment: &[u8; 32],
) -> Instruction {
    let holder_ata = derive_user_ata(holder, mint);
    let (grant_pda, _) = derive_grant_pda(commitment);

    let mut data = Vec::with_capacity(8 + 32);
    data.extend_from_slice(&DISC_GRANT_RIGHT);
    data.extend_from_slice(commitment);

    let accounts = vec![
        AccountMeta::new_readonly(*pool_pda, false),
        AccountMeta::new_readonly(*drt_config_pda, false),
        AccountMeta::new(*mint, false),
        AccountMeta::new(*holder, true),
        AccountMeta::new(holder_ata, false),
        AccountMeta::new(grant_pda, false),
        AccountMeta::new_readonly(token_program_id(), false),
        AccountMeta::new_readonly(system_program_id(), false),
    ];

    Instruction {
        program_id: drt_program_id(),
        accounts,
        data,
    }
}

// ============================================================================
// revoke_grant
// ============================================================================

/// Build the `revoke_grant` instruction (closes the Grant PDA, refunding its
/// rent to the pool owner).
///
/// Accounts (in IDL order): owner (writable, signer), pool, drt_config,
/// grant (writable, PDA from commitment).
pub fn build_revoke_grant(
    owner: &Pubkey,
    pool_pda: &Pubkey,
    drt_config_pda: &Pubkey,
    commitment: &[u8; 32],
) -> Instruction {
    let (grant_pda, _) = derive_grant_pda(commitment);

    let mut data = Vec::with_capacity(8 + 32);
    data.extend_from_slice(&DISC_REVOKE_GRANT);
    data.extend_from_slice(commitment);

    let accounts = vec![
        AccountMeta::new(*owner, true),
        AccountMeta::new_readonly(*pool_pda, false),
        AccountMeta::new_readonly(*drt_config_pda, false),
        AccountMeta::new(grant_pda, false),
    ];

    Instruction {
        program_id: drt_program_id(),
        accounts,
        data,
    }
}

// ============================================================================
// seal_pool
// ============================================================================

/// Build the `seal_pool` instruction.
///
/// Accounts (in IDL order): owner (signer), pool (writable).
pub fn build_seal_pool(owner: &Pubkey, pool_pda: &Pubkey) -> Instruction {
    let data = DISC_SEAL_POOL.to_vec();

    let accounts = vec![
        AccountMeta::new_readonly(*owner, true),
        AccountMeta::new(*pool_pda, false),
    ];

    Instruction {
        program_id: drt_program_id(),
        accounts,
        data,
    }
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use serde_json::Value;
    use solana_message::Message;
    use solana_transaction::Transaction;

    use super::*;
    use crate::blockchain::rpc::JsonRpcClient;
    use crate::config::DEFAULT_SOLANA_RPC_URL;

    /// Every builder lays out its accounts in the IDL's order, with its
    /// writable and signer flags, after the IDL's discriminator.
    #[test]
    fn builders_follow_the_idl() {
        let idl: Value =
            serde_json::from_str(include_str!("../../../idl/digital_rights_tokens.json")).unwrap();
        let spec = |name: &str| {
            let ix = idl["instructions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|ix| ix["name"] == name)
                .unwrap_or_else(|| panic!("{name} is in the IDL"));
            let flags: Vec<(bool, bool)> = ix["accounts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| {
                    let flag = |key: &str| a[key].as_bool().unwrap_or(false);
                    (flag("writable"), flag("signer"))
                })
                .collect();
            let disc: Vec<u8> = serde_json::from_value(ix["discriminator"].clone()).unwrap();
            (disc, flags)
        };
        let built = |ix: Instruction| {
            let flags = ix
                .accounts
                .iter()
                .map(|a| (a.is_writable, a.is_signer))
                .collect();
            (ix.data[..8].to_vec(), flags)
        };
        let [owner, pool, config, mint] = [1u8, 2, 3, 4].map(|n| Pubkey::new_from_array([n; 32]));
        let commitment = [5; 32];
        let register =
            build_register_drt(&owner, &pool, &owner, &[6; 16], "https://x", &[7; 32], 1).unwrap();
        for (name, ix) in [
            ("create_pool", build_create_pool(&owner, &pool, &[6; 16])),
            ("register_drt", register),
            (
                "grant_right",
                build_grant_right(&pool, &config, &mint, &owner, &commitment),
            ),
            (
                "revoke_grant",
                build_revoke_grant(&owner, &pool, &config, &commitment),
            ),
            ("seal_pool", build_seal_pool(&owner, &pool)),
        ] {
            assert_eq!(built(ix), spec(name), "{name}");
        }
        let revoke = build_revoke_grant(&owner, &pool, &config, &commitment);
        assert_eq!(revoke.accounts[3].pubkey, derive_grant_pda(&commitment).0);
        assert_eq!(revoke.data[8..], commitment);
    }

    /// A devnet pool with landed issuance burns; `GRANT_GUARD_POOL` names another.
    const DEVNET_POOL: &str = "3QhZF66CnE8prTFYwoETNuLdtya2mB8CtnJZ4EsML7XH";

    /// A `grant_right` that landed: its transaction, accounts and commitment.
    struct LandedGrant {
        signature: String,
        accounts: Vec<Pubkey>,
        commitment: [u8; 32],
    }

    /// The newest `grant_right` among the last 100 transactions that touched `pool`.
    async fn landed_grant(rpc: &JsonRpcClient, pool: &Pubkey) -> LandedGrant {
        let history = rpc
            .get_signatures_for_address(pool, None, None, Some(100), "finalized")
            .await
            .unwrap();
        for entry in history.iter().filter(|s| s.err.is_none()) {
            let tx = rpc.get_legacy_transaction(&entry.signature).await.unwrap();
            let keys = &tx.message.account_keys;
            let grant = tx.message.instructions.iter().find(|ix| {
                keys[usize::from(ix.program_id_index)] == drt_program_id()
                    && ix.data.starts_with(&DISC_GRANT_RIGHT)
            });
            if let Some(ix) = grant {
                return LandedGrant {
                    signature: entry.signature.clone(),
                    accounts: ix.accounts.iter().map(|&i| keys[usize::from(i)]).collect(),
                    commitment: ix.data[8..40].try_into().unwrap(),
                };
            }
        }
        panic!("no grant_right among the last 100 transactions of {pool}");
    }

    /// `ix` in an unsigned transaction paid by `payer`, simulated.
    async fn simulate(
        rpc: &JsonRpcClient,
        ix: Instruction,
        payer: &Pubkey,
    ) -> (Option<Value>, Vec<String>) {
        let tx = Transaction::new_unsigned(Message::new(&[ix], Some(payer)));
        let encoded = BASE64.encode(bincode::serialize(&tx).unwrap());
        rpc.simulate_transaction(&encoded).await.unwrap()
    }

    /// The program refuses a second `grant_right` under a commitment whose
    /// Grant PDA exists, while the same instruction under a fresh commitment
    /// passes, so the commitment alone decides; and `revoke_grant` from the
    /// pool's owner closes that Grant PDA. Simulated without signature
    /// checks, so it needs no keys and spends nothing.
    #[tokio::test]
    #[ignore = "calls devnet: run with `just grant-guard`"]
    async fn devnet_refuses_a_second_grant_under_one_commitment() {
        let url = std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| DEFAULT_SOLANA_RPC_URL.into());
        let rpc = JsonRpcClient::new(&url, "confirmed");
        let pool: Pubkey = std::env::var("GRANT_GUARD_POOL")
            .unwrap_or_else(|_| DEVNET_POOL.into())
            .parse()
            .unwrap();

        let landed = landed_grant(&rpc, &pool).await;
        let [pool, drt_config, mint, holder] = [0, 1, 2, 3].map(|i| landed.accounts[i]);
        let again = build_grant_right(&pool, &drt_config, &mint, &holder, &landed.commitment);
        let names: Vec<Pubkey> = again.accounts.iter().map(|a| a.pubkey).collect();
        assert_eq!(
            names, landed.accounts,
            "the rebuilt instruction is the landed one"
        );
        let (grant_pda, _) = derive_grant_pda(&landed.commitment);
        assert!(rpc.account_exists(&grant_pda, "finalized").await.unwrap());

        let (refused, logs) = simulate(&rpc, again, &holder).await;
        let Some(refusal) = refused else {
            panic!(
                "a second grant under {}'s commitment passed: {logs:#?}",
                landed.signature
            );
        };

        let ids = [
            *uuid::Uuid::new_v4().as_bytes(),
            *uuid::Uuid::new_v4().as_bytes(),
        ];
        let fresh: [u8; 32] = ids.concat().try_into().unwrap();
        let control = build_grant_right(&pool, &drt_config, &mint, &holder, &fresh);
        let (failed, control_logs) = simulate(&rpc, control, &holder).await;
        assert!(
            failed.is_none(),
            "a fresh commitment failed too, so the test shows nothing: {failed:?} {control_logs:#?}"
        );

        // An issuance's holder is the pool's owner.
        let revoke = build_revoke_grant(&holder, &pool, &drt_config, &landed.commitment);
        let (refused_close, close_logs) = simulate(&rpc, revoke, &holder).await;
        assert!(
            refused_close.is_none(),
            "revoke_grant failed: {refused_close:?} {close_logs:#?}"
        );

        eprintln!(
            "{} again, under the same commitment: {refusal}",
            landed.signature
        );
        for line in &logs {
            eprintln!("  {line}");
        }
    }
}
