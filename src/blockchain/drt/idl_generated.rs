// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Constants derived from the Anchor IDL
//! ([`idl/digital_rights_tokens.json`]).
//!
//! When the smart contract changes, update the IDL JSON and copy the new
//! discriminators here. Anchor discriminators are the first 8 bytes of
//! `sha256("global:<instruction_name>")` (for instructions),
//! `sha256("account:<AccountName>")` (for accounts), and
//! `sha256("event:<EventName>")` (for events).
//!
//! Not all constants are used by the client — that's expected and intentional.
#![allow(dead_code)]

/// Deployed program address (from IDL).
pub const IDL_PROGRAM_ADDRESS: &str = "8N5hVnK81rWhwfhxt9LfjrbeVT83Jjgy4dKyy4q6HKjk";

// ── Instruction discriminators ──────────────────────────────────

pub const DISC_CREATE_POOL: [u8; 8] = [233, 146, 209, 142, 207, 104, 64, 188];
pub const DISC_REGISTER_DRT: [u8; 8] = [132, 234, 232, 157, 1, 204, 22, 238];
pub const DISC_GRANT_RIGHT: [u8; 8] = [147, 166, 175, 167, 132, 161, 76, 232];
pub const DISC_REVOKE_GRANT: [u8; 8] = [134, 180, 57, 39, 152, 7, 154, 98];
pub const DISC_SEAL_POOL: [u8; 8] = [132, 120, 144, 83, 244, 251, 12, 246];

// ── Account discriminators ──────────────────────────────────────

pub const DISC_POOL_ACCOUNT: [u8; 8] = [241, 154, 109, 4, 17, 177, 109, 188];
pub const DISC_DRT_CONFIG_ACCOUNT: [u8; 8] = [20, 160, 51, 9, 64, 97, 106, 78];
pub const DISC_GRANT_ACCOUNT: [u8; 8] = [161, 166, 11, 205, 204, 135, 205, 54];

// ── Event discriminators ────────────────────────────────────────

pub const DISC_POOL_CREATED: [u8; 8] = [202, 44, 41, 88, 104, 220, 157, 82];
pub const DISC_DRT_REGISTERED: [u8; 8] = [244, 243, 67, 47, 173, 89, 107, 3];
pub const DISC_RIGHT_GRANTED: [u8; 8] = [251, 86, 219, 230, 109, 252, 94, 16];
pub const DISC_RIGHT_REVOKED: [u8; 8] = [67, 219, 188, 196, 202, 34, 65, 52];
pub const DISC_POOL_SEALED: [u8; 8] = [16, 227, 75, 106, 133, 87, 48, 68];

// ── Program error codes ─────────────────────────────────────────

pub const ERR_UNAUTHORIZED: u32 = 6000;
pub const ERR_CODE_REPO_URL_TOO_LONG: u32 = 6001;
pub const ERR_DRT_POOL_MISMATCH: u32 = 6002;
pub const ERR_DRT_MINT_MISMATCH: u32 = 6003;
pub const ERR_GRANT_DRT_MISMATCH: u32 = 6004;
pub const ERR_POOL_SEALED: u32 = 6005;
