// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! DRT (Digital Rights Token) smart contract integration.
//!
//! Provides Borsh-based instruction building, PDA derivation, on-chain account
//! deserialisation, and Anchor event parsing for the deployed
//! `digital_rights_tokens` program
//! (`8N5hVnK81rWhwfhxt9LfjrbeVT83Jjgy4dKyy4q6HKjk`).

pub mod accounts;
pub mod events;
pub mod idl_generated;
pub mod instructions;
pub mod pda;
pub mod types;
pub mod validation;
