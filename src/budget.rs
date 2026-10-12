// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The worker's budget for the large values it holds: uploads while they're
//! read, decrypted datasets and analysis tables. Each reserves its bytes
//! before allocating them and gives them back when its last owner drops
//! it, cached or not, so the memory they hold stays within the budget. A
//! request that can't reserve in time gets `503 worker_busy` rather than
//! the process running out of memory.
//!
//! `MEMORY_BUDGET_MIB` sets it against the worker's memory limit: by
//! default 2 GiB of the pilot's 3 GiB, leaving the rest to what it doesn't
//! count, such as the runtime, connections, the sealed-document cache,
//! which has a byte limit of its own, and a request's transient copies.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::ApiError;

/// Reservations round up to whole units.
const UNIT: usize = 64 << 10;

/// The budget when `MEMORY_BUDGET_MIB` doesn't set one.
pub const DEFAULT_MIB: usize = 2048;

/// The units that hold `bytes`, rounded up, and at least one.
fn units(bytes: usize) -> usize {
    bytes.div_ceil(UNIT).max(1)
}

/// `503 worker_busy`: the bytes didn't free up in time.
fn busy() -> ApiError {
    let mut e = ApiError::service_unavailable(
        "the worker's memory is taken by other requests; retry shortly",
    )
    .with_code("worker_busy");
    e.retry_after = Some(1);
    e
}

/// Bytes the budget can never give at once.
fn too_large(bytes: usize) -> ApiError {
    ApiError::unprocessable(format!(
        "this needs {} MiB of memory at once, more than the worker has",
        bytes >> 20
    ))
    .with_code("too_large_for_memory")
}

pub struct Budget {
    units: Arc<Semaphore>,
    bytes: usize,
}

/// Bytes reserved from a [`Budget`], given back when it's dropped.
#[derive(Debug)]
pub struct Reservation {
    permit: OwnedSemaphorePermit,
}

impl Budget {
    /// A budget of `bytes`, rounded up to whole units, and at most what a
    /// semaphore can count.
    pub fn new(bytes: usize) -> Self {
        let units = units(bytes).min(Semaphore::MAX_PERMITS);
        Self {
            units: Arc::new(Semaphore::new(units)),
            bytes: units * UNIT,
        }
    }

    /// The whole budget, in bytes.
    #[cfg(test)]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Reserve `bytes`, waiting up to `wait` for others to give theirs back.
    pub async fn reserve(&self, bytes: usize, wait: Duration) -> Result<Reservation, ApiError> {
        let wanted = units(bytes);
        let Ok(count) = u32::try_from(wanted) else {
            return Err(too_large(bytes));
        };
        if wanted * UNIT > self.bytes {
            return Err(too_large(bytes));
        }
        let permit = tokio::time::timeout(wait, self.units.clone().acquire_many_owned(count))
            .await
            .map_err(|_| busy())?
            .map_err(|_| ApiError::internal("the memory budget is closed"))?;
        Ok(Reservation { permit })
    }

    /// The bytes no one holds now.
    #[cfg(test)]
    pub fn available(&self) -> usize {
        self.units.available_permits() * UNIT
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::new(DEFAULT_MIB << 20)
    }
}

impl Reservation {
    /// The bytes it holds.
    #[cfg(test)]
    pub fn bytes(&self) -> usize {
        self.permit.num_permits() * UNIT
    }

    /// Hold `bytes`: give back what's more, or reserve what's missing from
    /// `budget`, waiting up to `wait`.
    pub async fn resize(
        &mut self,
        budget: &Budget,
        bytes: usize,
        wait: Duration,
    ) -> Result<(), ApiError> {
        let (wanted, held) = (units(bytes), self.permit.num_permits());
        if wanted < held {
            drop(self.permit.split(held - wanted));
        } else if wanted > held {
            if wanted.saturating_mul(UNIT) > budget.bytes {
                return Err(too_large(bytes));
            }
            let more = budget.reserve((wanted - held) * UNIT, wait).await?;
            self.permit.merge(more.permit);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WAIT: Duration = Duration::from_millis(50);

    #[tokio::test]
    async fn reservations_hold_bytes_until_dropped_and_resize() {
        let budget = Budget::new(10 * UNIT);
        let mut a = budget.reserve(4 * UNIT, WAIT).await.unwrap();
        assert_eq!((a.bytes(), budget.available()), (4 * UNIT, 6 * UNIT));
        // What doesn't fit waits, then is refused as busy.
        let refused = budget.reserve(7 * UNIT, WAIT).await.unwrap_err();
        assert_eq!(refused.code, "worker_busy");
        // More than the whole budget is refused at once.
        let never = budget.reserve(11 * UNIT, WAIT).await.unwrap_err();
        assert_eq!(never.code, "too_large_for_memory");

        a.resize(&budget, UNIT + 1, WAIT).await.unwrap();
        assert_eq!((a.bytes(), budget.available()), (2 * UNIT, 8 * UNIT));
        a.resize(&budget, 9 * UNIT, WAIT).await.unwrap();
        assert_eq!(budget.available(), UNIT);
        assert_eq!(
            a.resize(&budget, 11 * UNIT, WAIT).await.unwrap_err().code,
            "too_large_for_memory"
        );
        let b = budget.reserve(UNIT, WAIT).await.unwrap();
        drop(a);
        assert_eq!(budget.available(), 9 * UNIT);
        drop(b);
        assert_eq!(budget.available(), 10 * UNIT);

        // A waiting reservation gets bytes as soon as they're given back.
        let held = budget.reserve(10 * UNIT, WAIT).await.unwrap();
        let waiting = budget.reserve(UNIT, Duration::from_secs(5));
        let (waited, ()) = tokio::join!(waiting, async move {
            tokio::time::sleep(WAIT).await;
            drop(held);
        });
        assert_eq!(waited.unwrap().bytes(), UNIT);
    }
}
