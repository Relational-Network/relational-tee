// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Approved SQL analyses. A pool's Execute DRT pins a definition, a TOML
//! file holding the pool's columns, the filters a request may use and the
//! SQL ([`definition`]). For each caller, the worker builds an in-memory
//! SQLite table of only the rows the caller's employer scope allows
//! ([`table`]), and runs the definition's SQL on it with the request's
//! values bound as parameters ([`query`]). [`runner`] caches the
//! definitions, datasets and tables, and bounds how much runs at once.

pub mod cache;
pub mod dates;
pub mod definition;
pub mod fetch;
pub mod query;
pub mod runner;
pub mod table;
