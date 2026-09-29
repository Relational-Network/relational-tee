// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Background transaction indexer.
//!
//! Periodically polls Solana for new signatures on watched addresses and
//! stores them in the [`TxDatabase`]. Each wallet address registered via
//! [`TxDatabase::register_address`] is monitored.
//!
//! The indexer runs on a Tokio interval timer and stores the last-seen
//! signature per address in redb's `INDEXER_STATE` table so it only
//! fetches truly new transactions on each poll.

pub mod poller;
