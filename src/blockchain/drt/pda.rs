// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! PDA derivation for the `digital_rights_tokens` program.
//!
//! Seeds must match the on-chain Anchor program exactly:
//! - Pool: `["pool", pool_uuid (16 bytes)]`
//! - DrtConfig: `["drt", pool_pda, right_id (16 bytes)]`
//! - Mint: `["mint", pool_pda, right_id (16 bytes)]`
//! - Grant: `["grant", commitment (32 bytes)]`

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use solana_pubkey::Pubkey;
use std::str::FromStr;
use std::sync::OnceLock;
use zeroize::Zeroizing;

use super::types::{ASSOCIATED_TOKEN_PROGRAM_ID_STR, TOKEN_PROGRAM_ID_STR};
use crate::config::drt_program_id;
use crate::tee::EcKey;

/// Derive the Pool PDA from a 16-byte uuid.
pub fn derive_pool_pda(pool_uuid: &[u8; 16]) -> (Pubkey, u8) {
    let program_id = drt_program_id();
    Pubkey::find_program_address(&[b"pool", pool_uuid.as_ref()], &program_id)
}

/// Derive the DrtConfig PDA.
pub fn derive_drt_config_pda(pool: &Pubkey, right_id: &[u8; 16]) -> (Pubkey, u8) {
    let program_id = drt_program_id();
    Pubkey::find_program_address(&[b"drt", pool.as_ref(), right_id.as_ref()], &program_id)
}

/// Derive the DRT Mint PDA.
pub fn derive_mint_pda(pool: &Pubkey, right_id: &[u8; 16]) -> (Pubkey, u8) {
    let program_id = drt_program_id();
    Pubkey::find_program_address(&[b"mint", pool.as_ref(), right_id.as_ref()], &program_id)
}

/// Derive the Grant PDA for a given commitment.
pub fn derive_grant_pda(commitment: &[u8; 32]) -> (Pubkey, u8) {
    let program_id = drt_program_id();
    Pubkey::find_program_address(&[b"grant", commitment.as_ref()], &program_id)
}

/// Derive an Associated Token Account for the legacy SPL Token program.
///
/// Seeds: `[holder, TOKEN_PROGRAM, mint]` under the ATA program.
pub fn derive_user_ata(holder: &Pubkey, mint: &Pubkey) -> Pubkey {
    static TOKEN_PROGRAM: OnceLock<Pubkey> = OnceLock::new();
    static ATA_PROGRAM: OnceLock<Pubkey> = OnceLock::new();
    let token_program = TOKEN_PROGRAM.get_or_init(|| {
        Pubkey::from_str(TOKEN_PROGRAM_ID_STR).expect("valid SPL Token program ID")
    });
    let ata_program = ATA_PROGRAM.get_or_init(|| {
        Pubkey::from_str(ASSOCIATED_TOKEN_PROGRAM_ID_STR).expect("valid ATA program ID")
    });
    Pubkey::find_program_address(
        &[holder.as_ref(), token_program.as_ref(), mint.as_ref()],
        ata_program,
    )
    .0
}

/// Computes grant commitments: HMAC-SHA256 under a key derived from the
/// environment's `commitment-key`. Only a worker holds the key, so only a
/// worker can tell which Grant PDA belongs to which record. The key never
/// changes within an environment, because every Grant PDA depends on it. It
/// zeroizes on drop.
pub struct Commitments {
    key: Zeroizing<[u8; 32]>,
}

impl Commitments {
    /// `k_commit`: HKDF-SHA256 over `commitment-key`'s private scalar.
    pub fn derive(commitment_key: &EcKey) -> Self {
        let ikm = Zeroizing::new(commitment_key.secret().to_bytes());
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(b"relational-tee/commitment"), &ikm)
            .expand(b"k-commit-v1", key.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Self { key }
    }

    /// The commitment of `subject_id` (an issuance's record ID) to the right
    /// `right_id` in the pool `pool_uuid`.
    pub fn commitment(
        &self,
        subject_id: &str,
        pool_uuid: &[u8; 16],
        right_id: &[u8; 16],
    ) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.key.as_ref())
            .expect("HMAC takes any key length");
        mac.update(subject_id.as_bytes());
        mac.update(pool_uuid);
        mac.update(right_id);
        mac.finalize().into_bytes().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::tests::fixed_key;

    const SUBJECT: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
    const POOL_UUID: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const RIGHT_ID: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];

    #[test]
    fn commitments_match_the_reference_vector() {
        // Computed separately, with Python's hmac and hashlib, for the dev
        // key with scalar 0x42 00 … 00 09.
        let commitments = Commitments::derive(&fixed_key(9));
        assert_eq!(
            hex::encode(commitments.commitment(SUBJECT, &POOL_UUID, &RIGHT_ID)),
            "f7e8589760e209f622ea62f9ad33f8c7c90120a69bcf01c7f37846adf78d0a2c"
        );
    }

    #[test]
    fn another_key_or_subject_gives_another_commitment() {
        let one = Commitments::derive(&fixed_key(9));
        let other = Commitments::derive(&fixed_key(10));
        let commitment = one.commitment(SUBJECT, &POOL_UUID, &RIGHT_ID);
        assert_ne!(commitment, other.commitment(SUBJECT, &POOL_UUID, &RIGHT_ID));
        assert_ne!(commitment, one.commitment("another", &POOL_UUID, &RIGHT_ID));
        assert_eq!(commitment, one.commitment(SUBJECT, &POOL_UUID, &RIGHT_ID));
    }
}
