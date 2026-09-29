// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! IDs derived from an idempotent request's scope, so every retry of one
//! user action derives the same IDs and two users' keys can never collide.
//! Each is a UUIDv5 under a fixed namespace, over its parts joined with
//! newlines; the key is in canonical lowercase form.

use uuid::Uuid;

const NS_POOL: Uuid = Uuid::from_u128(0xc06b6eaf_274a_4fe9_aa82_42674f02dd5f);
const NS_RIGHT: Uuid = Uuid::from_u128(0x94e9b231_3cd0_4bae_98b5_896bac2955ba);
const NS_UPLOAD: Uuid = Uuid::from_u128(0x55197cf0_95e9_4cc8_86f0_28002664cb46);
const NS_WALLET: Uuid = Uuid::from_u128(0xba3ecd19_e66f_4fe6_9da7_dce668a690d6);

fn v5(namespace: &Uuid, parts: &[&str]) -> Uuid {
    Uuid::new_v5(namespace, parts.join("\n").as_bytes())
}

/// A new pool's UUID, which fixes its PDA (`["pool", pool_uuid]`).
pub fn pool_uuid(user_id: &str, key: &str) -> [u8; 16] {
    *v5(&NS_POOL, &[user_id, key]).as_bytes()
}

/// A new pool's DRT right ID.
pub fn right_id(pool_uuid: &[u8; 16], drt_name: &str) -> [u8; 16] {
    let pool = Uuid::from_bytes(*pool_uuid).hyphenated().to_string();
    *v5(&NS_RIGHT, &[&pool, drt_name]).as_bytes()
}

/// An upload's ID, which names its dataset and, for an issuance, is its
/// `record_id`, so it fixes the grant commitment.
pub fn upload_id(user_id: &str, pool_pda: &str, key: &str) -> String {
    v5(&NS_UPLOAD, &[user_id, pool_pda, key]).to_string()
}

/// A new wallet's ID.
pub fn wallet_id(user_id: &str, key: &str) -> String {
    v5(&NS_WALLET, &[user_id, key]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";

    #[test]
    fn ids_are_pinned() {
        // Python's uuid.uuid5 over the same namespaces and names.
        let pool = pool_uuid("user-1", KEY);
        assert_eq!(
            Uuid::from_bytes(pool).to_string(),
            "72830ada-a074-508f-b959-8f112671d414"
        );
        assert_eq!(
            Uuid::from_bytes(right_id(&pool, "append")).to_string(),
            "37c4490d-bbc3-54b0-a6b7-f2e908c9310b"
        );
        assert_eq!(
            upload_id("user-1", "Pool1", KEY),
            "78cd47fd-343c-5b67-8273-28541168179e"
        );
        assert_eq!(
            wallet_id("user-1", KEY),
            "d3ae4a7c-7d0c-596d-a233-557dcbd494b1"
        );
    }

    #[test]
    fn two_users_with_one_key_get_different_ids() {
        assert_eq!(
            wallet_id("user-2", KEY),
            "6663469c-95a1-51c8-a19d-ab5e6fa48290"
        );
        assert_ne!(
            upload_id("user-1", "Pool1", KEY),
            upload_id("user-2", "Pool1", KEY)
        );
        assert_ne!(pool_uuid("user-1", KEY), pool_uuid("user-2", KEY));
        assert_ne!(
            upload_id("user-1", "Pool1", KEY),
            upload_id("user-1", "Pool2", KEY)
        );
    }
}
