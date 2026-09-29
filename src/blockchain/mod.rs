// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Solana blockchain interaction: RPC client, transaction building, signing.

pub mod client;
pub mod drt;
pub mod rpc;
pub mod signing;
pub mod spl_token;
pub mod transactions;
pub mod types;

pub use client::SolanaClient;
