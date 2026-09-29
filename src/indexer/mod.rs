// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Background transaction indexer.
//!
//! Polls Solana for new signatures on our wallets' addresses and stores the
//! transactions in each wallet's history. It keeps the last signature seen
//! per address in the shared sync rows, so it only fetches new transactions.
//! The continuous loop is off (`INDEXER_ENABLED`); list requests sync on
//! demand.

pub mod poller;
