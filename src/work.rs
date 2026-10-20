// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Keeping synchronous work from holding the worker hostage.
//!
//! - [`Threads`] runs analysis work on blocking threads, about one per CPU
//!   at a time. Each job gets a [`Stop`] that fires at its deadline or once
//!   the request that asked for it is gone, and checks it as it goes, so a
//!   timed-out or abandoned job gives its thread back. Work that goes on in
//!   a task of its own links its stops to the request's [`Cancel`].
//! - [`cpu`] runs a request's CPU-heavy step, such as opening a sealed
//!   upload, off the async threads, so other requests and health checks
//!   keep being served. What can reach it is bounded by the memory budget.
//! - [`supervise`] restarts a long-lived background task that stops, and
//!   says so in the log.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::runtime::{Handle, RuntimeFlavor};
use tokio::sync::{Notify, Semaphore};
use tracing::{error, warn};

use crate::error::ApiError;

/// How long a job waits for a free thread before it gets 503.
pub const QUEUE_WAIT: Duration = Duration::from_secs(1);

/// When work should stop: at a deadline, once it's abandoned, or once the
/// request it's linked to is cancelled.
#[derive(Clone, Debug)]
pub struct Stop {
    deadline: Instant,
    abandoned: Arc<AtomicBool>,
    cancelled: Option<Cancelled>,
}

/// A request's cancellation, for work that goes on in a task of its own
/// when the request's future is dropped, as it is when its client goes
/// away: dropping this fires every [`Stop`] linked to its [`Cancelled`],
/// and ends every [`Cancelled::wait`].
/// Each step of the work gets a stop of its own, since a stop is abandoned
/// once its step ends, and they share the request's flag.
#[derive(Debug, Default)]
pub struct Cancel(Cancelled);

impl Cancel {
    /// The flag the work reads.
    pub fn watch(&self) -> Cancelled {
        self.0.clone()
    }
}

impl Drop for Cancel {
    fn drop(&mut self) {
        self.0 .0.set.store(true, Ordering::SeqCst);
        self.0 .0.notify.notify_waiters();
    }
}

/// Whether a request's [`Cancel`] has been dropped.
#[derive(Clone, Debug, Default)]
pub struct Cancelled(Arc<Flag>);

#[derive(Debug, Default)]
struct Flag {
    set: AtomicBool,
    notify: Notify,
}

impl Cancelled {
    pub fn is_set(&self) -> bool {
        self.0.set.load(Ordering::SeqCst)
    }

    /// Wait until it's set.
    pub async fn wait(&self) {
        let mut notified = std::pin::pin!(self.0.notify.notified());
        notified.as_mut().enable();
        if !self.is_set() {
            notified.await;
        }
    }
}

/// Work stopped before it finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stopped;

impl std::fmt::Display for Stopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the work ran out of time")
    }
}

impl std::error::Error for Stopped {}

impl Stop {
    /// Stop at `deadline`.
    pub fn at(deadline: Instant) -> Self {
        Self {
            deadline,
            abandoned: Arc::default(),
            cancelled: None,
        }
    }

    /// Stop once `time` has passed.
    pub fn after(time: Duration) -> Self {
        Self::at(Instant::now() + time)
    }

    /// This stop, which also fires once `cancelled` is set.
    pub fn linked(mut self, cancelled: &Cancelled) -> Self {
        self.cancelled = Some(cancelled.clone());
        self
    }

    /// Whether the work should stop now.
    pub fn stopped(&self) -> bool {
        self.abandoned.load(Ordering::Relaxed)
            || self.cancelled.as_ref().is_some_and(Cancelled::is_set)
            || Instant::now() >= self.deadline
    }

    /// [`Self::stopped`] as an error, for `?`.
    pub fn check(&self) -> Result<(), Stopped> {
        if self.stopped() {
            Err(Stopped)
        } else {
            Ok(())
        }
    }

    /// Stop the work now, whatever its deadline: nobody waits for it.
    pub fn abandon(&self) {
        self.abandoned.store(true, Ordering::Relaxed);
    }
}

/// Abandons its stop when dropped: when the future waiting for the work is.
struct AbandonOnDrop(Stop);

impl Drop for AbandonOnDrop {
    fn drop(&mut self) {
        self.0.abandon();
    }
}

/// `503 analysis_busy`: no thread freed up within [`QUEUE_WAIT`].
fn busy() -> ApiError {
    let mut e =
        ApiError::service_unavailable("the worker is busy with other analyses; retry shortly")
            .with_code("analysis_busy");
    e.retry_after = Some(1);
    e
}

/// Blocking threads for analysis work, a few at a time.
pub struct Threads {
    permits: Arc<Semaphore>,
    count: usize,
}

impl Default for Threads {
    /// One per CPU.
    fn default() -> Self {
        Self::new(std::thread::available_parallelism().map_or(2, |n| n.get()))
    }
}

impl Threads {
    /// Threads for `count` jobs at a time.
    pub fn new(count: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(count)),
            count,
        }
    }

    /// How many jobs run at a time.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Run `work` on a blocking thread once one is free, or 503 if none
    /// frees up within [`QUEUE_WAIT`]. `work` should stop when its [`Stop`]
    /// fires: at `stop`'s deadline, or once this future is dropped.
    pub async fn run<T: Send + 'static>(
        &self,
        stop: Stop,
        work: impl FnOnce(&Stop) -> Result<T, ApiError> + Send + 'static,
    ) -> Result<T, ApiError> {
        let abandon = AbandonOnDrop(stop);
        let permit = tokio::time::timeout(QUEUE_WAIT, self.permits.clone().acquire_owned())
            .await
            .map_err(|_| busy())?
            .map_err(|_| ApiError::internal("the analysis threads are closed"))?;
        let stop = abandon.0.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work(&stop)
        })
        .await
        .map_err(|e| ApiError::internal(format!("an analysis task failed: {e}")))?
    }

    /// The threads no job holds now.
    #[cfg(test)]
    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }
}

/// Run `work`, a request's CPU-heavy step, without holding up the async
/// threads' other tasks. In-process tests' single-threaded runtimes run it
/// in place.
pub fn cpu<T>(work: impl FnOnce() -> T) -> T {
    match Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(RuntimeFlavor::MultiThread) => tokio::task::block_in_place(work),
        _ => work(),
    }
}

/// Inputs smaller than this are worked on in place: moving off the async
/// thread would cost more than it saves.
const CPU_HEAVY_BYTES: usize = 256 << 10;

/// [`cpu`], for work proportional to `bytes` of input.
pub fn cpu_for<T>(bytes: usize, work: impl FnOnce() -> T) -> T {
    if bytes < CPU_HEAVY_BYTES {
        work()
    } else {
        cpu(work)
    }
}

/// How long to wait after `failures` failures in a row: none after none,
/// then `wait.0`, doubling up to `wait.1`.
pub fn backoff(failures: u32, wait: (Duration, Duration)) -> Duration {
    match failures {
        0 => Duration::ZERO,
        n => wait.0.saturating_mul(1 << (n - 1).min(16)).min(wait.1),
    }
}

/// How long a restarted background task waits first, at least and at most.
const RESTART_WAIT: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(60));

/// Run the background task `start` makes, and start it again whenever it
/// returns or panics, waiting longer each time it fails quickly. A task's
/// end is logged as an error, with `alert = "background_task_stopped"`.
pub fn supervise<F, Fut>(name: &'static str, mut start: F)
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut wait = RESTART_WAIT.0;
        loop {
            let started = tokio::time::Instant::now();
            match tokio::spawn(start()).await {
                Ok(()) => error!(
                    task = name,
                    alert = "background_task_stopped",
                    "A background task returned; restarting it"
                ),
                Err(e) if e.is_panic() => error!(
                    task = name,
                    alert = "background_task_stopped",
                    "A background task panicked; restarting it"
                ),
                // The runtime is shutting down.
                Err(_) => return,
            }
            if started.elapsed() > RESTART_WAIT.1 {
                wait = RESTART_WAIT.0;
            }
            warn!(
                task = name,
                wait_secs = wait.as_secs(),
                "Restarting a background task"
            );
            tokio::time::sleep(wait).await;
            wait = (wait * 2).min(RESTART_WAIT.1);
        }
    });
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    #[tokio::test]
    async fn an_abandoned_job_stops_and_gives_its_thread_back() {
        let threads = Arc::new(Threads::new(1));
        let (started, ended) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        let (s, e) = (started.clone(), ended.clone());
        let job = threads.run(Stop::after(Duration::from_secs(60)), move |stop| {
            s.store(true, Ordering::SeqCst);
            while !stop.stopped() {
                std::thread::sleep(Duration::from_millis(1));
            }
            e.store(true, Ordering::SeqCst);
            Ok(())
        });
        // The request gives up while the job runs.
        let gave_up = tokio::time::timeout(Duration::from_millis(50), job).await;
        assert!(gave_up.is_err());
        assert!(started.load(Ordering::SeqCst));
        for _ in 0..500 {
            if threads.available() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert!(ended.load(Ordering::SeqCst), "the job saw its stop");
        assert_eq!(threads.available(), 1, "and gave its thread back");
        assert_eq!(
            threads
                .run(Stop::after(Duration::from_secs(1)), |_| Ok(3))
                .await
                .unwrap(),
            3
        );
    }

    #[tokio::test]
    async fn a_job_waits_for_a_free_thread_and_then_gives_up() {
        let threads = Threads::new(1);
        let (started, release) = (
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(std::sync::Barrier::new(2)),
        );
        let (notify, wait) = (started.clone(), release.clone());
        let soon = || Stop::after(Duration::from_secs(5));
        let busy = threads.run(soon(), move |_| {
            notify.notify_one();
            wait.wait();
            Ok(1)
        });
        let refused = async {
            started.notified().await;
            let refused = threads.run(soon(), |_| Ok(2)).await;
            release.wait();
            refused
        };
        let (busy, refused) = tokio::join!(busy, refused);
        assert_eq!(busy.unwrap(), 1);
        let refused = refused.unwrap_err();
        assert_eq!(
            (refused.code, refused.retry_after),
            ("analysis_busy", Some(1))
        );
        assert_eq!(threads.run(soon(), |_| Ok(3)).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn linked_stops_fire_when_their_request_is_cancelled_and_not_before() {
        let threads = Threads::new(1);
        let cancel = Cancel::default();
        let cancelled = cancel.watch();
        let step = || Stop::after(Duration::from_secs(60)).linked(&cancelled);
        // A finished step abandons its own stop only.
        let first = step();
        let seen = first.clone();
        assert!(!threads.run(first, |stop| Ok(stop.stopped())).await.unwrap());
        assert!(seen.stopped());
        let second = step();
        assert!(!second.stopped() && !cancelled.is_set());
        drop(cancel);
        assert!(cancelled.is_set());
        assert!(second.stopped());
        assert!(!Stop::after(Duration::from_secs(60)).stopped(), "unlinked");
    }

    #[tokio::test]
    async fn waiting_for_a_cancellation_ends_when_its_request_goes() {
        let cancel = Cancel::default();
        let cancelled = cancel.watch();
        let waiting = tokio::spawn({
            let cancelled = cancelled.clone();
            async move { cancelled.wait().await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiting.is_finished());
        drop(cancel);
        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("the wait ends")
            .unwrap();
        // Once set, a wait ends at once.
        tokio::time::timeout(Duration::from_secs(5), cancelled.wait())
            .await
            .expect("an already-set wait ends");
    }

    #[tokio::test]
    async fn a_job_stops_at_its_deadline() {
        let threads = Threads::new(1);
        let result: Result<(), _> = threads
            .run(Stop::after(Duration::from_millis(20)), |stop| {
                while stop.check().is_ok() {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(ApiError::unprocessable("stopped"))
            })
            .await;
        assert_eq!(result.unwrap_err().message, "stopped");
    }

    #[tokio::test(start_paused = true)]
    async fn a_background_task_that_stops_is_started_again() {
        let starts = Arc::new(AtomicUsize::new(0));
        let counted = starts.clone();
        supervise("test", move || {
            let n = counted.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    panic!("the first run fails");
                }
                if n == 1 {
                    return;
                }
                std::future::pending::<()>().await;
            }
        });
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(
            starts.load(Ordering::SeqCst),
            3,
            "after a panic and a return"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cpu_work_leaves_the_async_threads_free() {
        let blocked = tokio::spawn(async {
            cpu(|| std::thread::sleep(Duration::from_millis(300)));
        });
        // Another task still runs promptly on the runtime meanwhile.
        let started = Instant::now();
        let others: Vec<_> = (0..4)
            .map(|_| tokio::spawn(async { tokio::time::sleep(Duration::from_millis(5)).await }))
            .collect();
        for other in others {
            other.await.unwrap();
        }
        assert!(started.elapsed() < Duration::from_millis(200));
        blocked.await.unwrap();
    }
}
