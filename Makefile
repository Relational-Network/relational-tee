# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# Host development shortcuts for the `cargo dev-*` aliases in .cargo/config.toml.

.PHONY: dev-check
dev-check:
	cargo dev-check

.PHONY: dev-build
dev-build:
	cargo dev-build

.PHONY: dev-test
dev-test:
	cargo dev-test
