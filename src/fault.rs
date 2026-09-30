// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Fault injection for the idempotency fault suite (dev builds only).
//!
//! A dev worker started with `FAULT_INJECTION=on` honours an `X-Fault-Exit`
//! request header naming one of the points below. When that request reaches
//! the point, the process exits at once with status 137, as if it had been
//! killed, keeping whatever the request had already written. The suite
//! crashes a worker at each step of a saga this way, then retries on
//! another. Release builds contain none of this: [`point`] does nothing.
//!
//! | Point | Reached |
//! |---|---|
//! | `staged` | after a pool creation or an issuance stages its saga |
//! | `tx_stored` | after a chain step stores its signed transaction, before sending it |
//! | `tx_sent` | after sending it, before it reaches its commitment |
//! | `tx_confirmed` | after it reaches its commitment |
//! | `recorded` | after the request's last document write, before its response is stored |

/// The request header that names the point to exit at.
#[cfg(feature = "dev")]
pub const HEADER: &str = "x-fault-exit";

#[cfg(feature = "dev")]
static ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "dev")]
tokio::task_local! {
    static EXIT_AT: Option<String>;
}

/// Honour `X-Fault-Exit` from now on (`FAULT_INJECTION=on`).
#[cfg(feature = "dev")]
pub fn enable() {
    ENABLED.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Exit here if the request asked to.
pub fn point(name: &'static str) {
    #[cfg(feature = "dev")]
    if EXIT_AT
        .try_with(|at| at.as_deref() == Some(name))
        .unwrap_or(false)
    {
        tracing::warn!(point = name, "Fault injection: exiting as if killed");
        std::process::exit(137);
    }
    #[cfg(not(feature = "dev"))]
    let _ = name;
}

/// Middleware: note the point a request asks to exit at, if fault
/// injection is on.
#[cfg(feature = "dev")]
pub async fn middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let at = ENABLED
        .load(std::sync::atomic::Ordering::SeqCst)
        .then(|| {
            request
                .headers()
                .get(HEADER)?
                .to_str()
                .ok()
                .map(String::from)
        })
        .flatten();
    EXIT_AT.scope(at, next.run(request)).await
}

#[cfg(all(test, feature = "dev"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn only_the_named_point_of_a_marked_request_would_exit() {
        // Outside a request, and at other points, nothing happens.
        point("staged");
        EXIT_AT
            .scope(Some("tx_sent".into()), async {
                point("staged");
                point("recorded");
                assert!(EXIT_AT.with(|at| at.as_deref() == Some("tx_sent")));
            })
            .await;
    }
}
