// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Anchor event parsing from Solana transaction logs.
//!
//! Anchor emits events as base64-encoded Borsh data prefixed with an 8-byte
//! discriminator. Events appear in transaction logs as:
//!
//! ```text
//! Program data: <base64-encoded-data>
//! ```

use base64::Engine;
use borsh::BorshDeserialize;
use solana_pubkey::Pubkey;

use super::types::*;

// ============================================================================
// Raw event structs (Borsh-deserialisable from log data)
// ============================================================================

#[derive(Debug, Clone, BorshDeserialize)]
pub struct PoolCreatedEvent {
    pub pool: Pubkey,
    pub uuid: [u8; 16],
    pub owner: Pubkey,
    pub created_at: i64,
}

#[derive(Debug, Clone, BorshDeserialize)]
pub struct DrtRegisteredEvent {
    pub pool: Pubkey,
    pub drt_config: Pubkey,
    pub mint: Pubkey,
    pub right_id: [u8; 16],
    pub supply: u64,
    pub code_hash: [u8; 32],
    pub created_at: i64,
}

#[derive(Debug, Clone, BorshDeserialize)]
pub struct RightGrantedEvent {
    pub pool: Pubkey,
    pub drt_config: Pubkey,
    pub commitment: [u8; 32],
    pub granted_at: i64,
}

#[derive(Debug, Clone, BorshDeserialize)]
pub struct RightRevokedEvent {
    pub pool: Pubkey,
    pub drt_config: Pubkey,
    pub commitment: [u8; 32],
    pub revoked_at: i64,
}

#[derive(Debug, Clone, BorshDeserialize)]
pub struct PoolSealedEvent {
    pub pool: Pubkey,
    pub sealed_at: i64,
}

// ============================================================================
// Unified event enum
// ============================================================================

#[derive(Debug, Clone)]
pub enum DrtEvent {
    PoolCreated(PoolCreatedEvent),
    DrtRegistered(DrtRegisteredEvent),
    RightGranted(RightGrantedEvent),
    RightRevoked(RightRevokedEvent),
    PoolSealed(PoolSealedEvent),
}

impl DrtEvent {
    pub fn to_response(&self) -> DrtEventResponse {
        match self {
            DrtEvent::PoolCreated(e) => DrtEventResponse::PoolCreated {
                pool: e.pool.to_string(),
                uuid: hex::encode(e.uuid),
                owner: e.owner.to_string(),
                created_at: e.created_at,
            },
            DrtEvent::DrtRegistered(e) => DrtEventResponse::DrtRegistered {
                pool: e.pool.to_string(),
                drt_config: e.drt_config.to_string(),
                mint: e.mint.to_string(),
                right_id: hex::encode(e.right_id),
                supply: e.supply,
                code_hash: hex::encode(e.code_hash),
                created_at: e.created_at,
            },
            DrtEvent::RightGranted(e) => DrtEventResponse::RightGranted {
                pool: e.pool.to_string(),
                drt_config: e.drt_config.to_string(),
                commitment: hex::encode(e.commitment),
                granted_at: e.granted_at,
            },
            DrtEvent::RightRevoked(e) => DrtEventResponse::RightRevoked {
                pool: e.pool.to_string(),
                drt_config: e.drt_config.to_string(),
                commitment: hex::encode(e.commitment),
                revoked_at: e.revoked_at,
            },
            DrtEvent::PoolSealed(e) => DrtEventResponse::PoolSealed {
                pool: e.pool.to_string(),
                sealed_at: e.sealed_at,
            },
        }
    }
}

// ============================================================================
// Parsing
// ============================================================================

const PROGRAM_DATA_PREFIX: &str = "Program data: ";

/// Parse DRT events from transaction log lines.
pub fn parse_drt_events(logs: &[String]) -> Vec<DrtEvent> {
    let mut events = Vec::new();

    for line in logs {
        let data_b64 = match line.strip_prefix(PROGRAM_DATA_PREFIX) {
            Some(s) => s.trim(),
            None => continue,
        };

        let bytes = match base64::engine::general_purpose::STANDARD.decode(data_b64) {
            Ok(b) => b,
            Err(_) => continue,
        };

        if bytes.len() < 8 {
            continue;
        }

        let disc: [u8; 8] = bytes[..8].try_into().unwrap();
        let payload = &bytes[8..];

        let event = match disc {
            DISC_POOL_CREATED => PoolCreatedEvent::try_from_slice(payload)
                .ok()
                .map(DrtEvent::PoolCreated),
            DISC_DRT_REGISTERED => DrtRegisteredEvent::try_from_slice(payload)
                .ok()
                .map(DrtEvent::DrtRegistered),
            DISC_RIGHT_GRANTED => RightGrantedEvent::try_from_slice(payload)
                .ok()
                .map(DrtEvent::RightGranted),
            DISC_RIGHT_REVOKED => RightRevokedEvent::try_from_slice(payload)
                .ok()
                .map(DrtEvent::RightRevoked),
            DISC_POOL_SEALED => PoolSealedEvent::try_from_slice(payload)
                .ok()
                .map(DrtEvent::PoolSealed),
            _ => None,
        };

        if let Some(e) = event {
            events.push(e);
        }
    }

    events
}

/// Fetch and parse DRT events from a confirmed transaction signature.
pub async fn parse_events_from_signature(
    rpc: &crate::blockchain::rpc::JsonRpcClient,
    signature_str: &str,
) -> Result<Vec<DrtEvent>, crate::error::ApiError> {
    parse_events_from_signature_with_commitment(rpc, signature_str, "confirmed").await
}

/// Fetch and parse DRT events at a specific commitment level.
pub async fn parse_events_from_signature_with_commitment(
    rpc: &crate::blockchain::rpc::JsonRpcClient,
    signature_str: &str,
    commitment: &str,
) -> Result<Vec<DrtEvent>, crate::error::ApiError> {
    let tx = rpc
        .get_transaction(signature_str, commitment)
        .await
        .map_err(|e| {
            crate::error::ApiError::service_unavailable(format!("failed to fetch transaction: {e}"))
        })?;

    let logs = tx.meta.map(|m| m.log_messages).unwrap_or_default();

    Ok(parse_drt_events(&logs))
}
