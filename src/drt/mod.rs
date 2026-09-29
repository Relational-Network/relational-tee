// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! DRT script lifecycle: verified fetch from GitHub, SHA-256 verification,
//! cached bytes on the encrypted FS, and (eventually) sandboxed execution
//! via a WASM runtime.
//!
//! The trust contract:
//! - Every executable DRT has `code_repo_url` + `code_hash` recorded on-chain
//!   in the `DrtConfig` PDA (see [`crate::blockchain::drt::types::DrtConfig`]).
//! - On-chain is the source of truth. A locally cached script is only used
//!   if its SHA-256 still matches the current on-chain `code_hash`.
//! - Scripts are fetched only from a curated allowlist (currently
//!   `raw.githubusercontent.com/relational-network/...`).

pub mod runtime;
pub mod verified_fetch;
