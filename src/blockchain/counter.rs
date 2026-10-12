// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! A pool's generation counter: an SPL Token mint whose supply is how many
//! access changes the pool's document has made, so a restored older
//! document shows a lower generation than the chain.
//!
//! The mint is at an address derived from the pool's owner and the pool
//! (`create_with_seed`, under the SPL Token program), so it can be found
//! from any version of the document, and only the owner's wallet, whose
//! key never leaves the worker, can create it or mint. Its tokens stay in
//! the owner's token account and are never burned. Each change mints one,
//! with a memo naming the generation, so every change's transaction is
//! unique. The first also creates the mint; lamports someone sent to its
//! address first don't stop that, as a transfer, `AllocateWithSeed` and
//! `InitializeMint2` work on an account that holds only lamports.

use std::str::FromStr;
use std::sync::OnceLock;

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use solana_system_interface::instruction as system_instruction;

use super::rpc::Account;
use super::spl_token::{
    create_ata_instruction, get_associated_token_address, spl_token_program_id,
};
use crate::error::ApiError;
use crate::ids;

/// An SPL Token mint's size.
pub const MINT_SIZE: u64 = 82;

const MEMO_PROGRAM_ID_STR: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

fn memo_program_id() -> &'static Pubkey {
    static ID: OnceLock<Pubkey> = OnceLock::new();
    ID.get_or_init(|| Pubkey::from_str(MEMO_PROGRAM_ID_STR).expect("valid Memo program ID"))
}

/// The counter of `pool_pda`, owned by `owner`.
pub fn counter_address(owner: &Pubkey, pool_pda: &str) -> Result<Pubkey, ApiError> {
    Pubkey::create_with_seed(
        owner,
        &ids::generation_seed(pool_pda),
        spl_token_program_id(),
    )
    .map_err(|e| ApiError::internal(format!("deriving a pool's counter: {e}")))
}

/// SPL Token `InitializeMint2`: no decimals, `authority` mints, no freeze
/// authority.
fn initialize_mint(mint: &Pubkey, authority: &Pubkey) -> Instruction {
    let mut data = vec![20, 0];
    data.extend_from_slice(authority.as_ref());
    data.push(0);
    Instruction {
        program_id: *spl_token_program_id(),
        accounts: vec![AccountMeta::new(*mint, false)],
        data,
    }
}

/// SPL Token `MintTo`.
fn mint_to(mint: &Pubkey, account: &Pubkey, authority: &Pubkey, amount: u64) -> Instruction {
    let mut data = vec![7];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: *spl_token_program_id(),
        accounts: vec![
            AccountMeta::new(*mint, false),
            AccountMeta::new(*account, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

fn memo(text: &str) -> Instruction {
    Instruction {
        program_id: *memo_program_id(),
        accounts: Vec::new(),
        data: text.as_bytes().to_vec(),
    }
}

/// The instructions that take `pool_pda`'s counter to `generation`. The
/// first generation's create the mint too, funding it with `rent`.
pub fn bump(
    owner: &Pubkey,
    pool_pda: &str,
    generation: u64,
    rent: u64,
) -> Result<Vec<Instruction>, ApiError> {
    let counter = counter_address(owner, pool_pda)?;
    let mut instructions = Vec::new();
    if generation == 1 {
        instructions.extend([
            system_instruction::transfer(owner, &counter, rent),
            system_instruction::allocate_with_seed(
                &counter,
                owner,
                &ids::generation_seed(pool_pda),
                MINT_SIZE,
                spl_token_program_id(),
            ),
            initialize_mint(&counter, owner),
        ]);
    }
    let account = get_associated_token_address(owner, &counter);
    instructions.extend([
        create_ata_instruction(owner, owner, &counter),
        mint_to(&counter, &account, owner, 1),
        memo(&format!("generation {generation} of pool {pool_pda}")),
    ]);
    Ok(instructions)
}

/// The generation `account`, the counter of a pool `owner` owns, shows:
/// none yet if there's no mint there.
pub fn generation(account: Option<&Account>, owner: &Pubkey) -> Result<u64, String> {
    let Some(account) = account else {
        return Ok(0);
    };
    if &account.owner != spl_token_program_id() {
        // Lamports sent to the address, before the first change made it.
        return if account.data.is_empty() {
            Ok(0)
        } else {
            Err("the counter's address holds another program's account".into())
        };
    }
    let data = &account.data;
    let authority_is_owner =
        data.get(..4) == Some(&[1, 0, 0, 0]) && data.get(4..36) == Some(owner.as_ref());
    if data.len() != MINT_SIZE as usize || data.get(45) != Some(&1) || !authority_is_owner {
        return Err("the counter isn't a mint the pool's owner mints".into());
    }
    data.get(36..44)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| "the counter's supply doesn't parse".into())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A counter mint `owner` mints, with `supply`.
    pub(crate) fn mint(owner: &Pubkey, supply: u64) -> Vec<u8> {
        let mut data = vec![0u8; MINT_SIZE as usize];
        data[..4].copy_from_slice(&[1, 0, 0, 0]);
        data[4..36].copy_from_slice(owner.as_ref());
        data[36..44].copy_from_slice(&supply.to_le_bytes());
        data[45] = 1;
        data
    }

    #[test]
    fn the_first_bump_creates_the_mint_and_every_bump_mints_one_with_a_memo() {
        let owner = Pubkey::new_from_array([4; 32]);
        let counter = counter_address(&owner, "P1").unwrap();
        assert_eq!(counter, counter_address(&owner, "P1").unwrap());
        assert_ne!(counter, counter_address(&owner, "P2").unwrap());

        let first = bump(&owner, "P1", 1, 1_461_600).unwrap();
        assert_eq!(first.len(), 6);
        assert_eq!(first[2].data[..2], [20, 0], "InitializeMint2, no decimals");
        assert_eq!(&first[2].data[2..34], owner.as_ref());
        let later = bump(&owner, "P1", 7, 0).unwrap();
        let [ata, mint, note] = later.as_slice() else {
            panic!("an account, a mint and a memo: {later:?}");
        };
        assert_eq!(ata.data, [1], "CreateIdempotent");
        assert_eq!(mint.data, [&[7][..], &1u64.to_le_bytes()].concat());
        assert_eq!(mint.accounts[0].pubkey, counter);
        assert_eq!(note.data, b"generation 7 of pool P1");
    }

    #[test]
    fn only_the_owners_mint_counts() {
        let owner = Pubkey::new_from_array([4; 32]);
        let token = |data: Vec<u8>| Account {
            owner: *spl_token_program_id(),
            lamports: 1,
            data,
        };
        assert_eq!(generation(None, &owner), Ok(0));
        let lamports = Account {
            owner: Pubkey::default(),
            lamports: 1,
            data: Vec::new(),
        };
        assert_eq!(generation(Some(&lamports), &owner), Ok(0));
        assert_eq!(generation(Some(&token(mint(&owner, 9))), &owner), Ok(9));
        let other = Pubkey::new_from_array([5; 32]);
        assert!(generation(Some(&token(mint(&other, 9))), &owner).is_err());
        assert!(generation(Some(&token(vec![0; 82])), &owner).is_err());
        assert!(generation(Some(&token(mint(&owner, 9)[..80].to_vec())), &owner).is_err());
    }
}
