// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The transport key versions a worker opens uploads with.
//!
//! The current version, released at startup, is always accepted. Any other
//! version is accepted while the reference-values manifest lists it with a
//! Key Vault `version`: the worker releases it through its key provider when
//! a manifest first lists it, checks that its thumbprint is the listed
//! `kid`, and drops it once a manifest no longer lists it. During a rotation
//! the manifest lists both versions, so every worker opens uploads sealed to
//! either, whichever it started with; the old one stops opening when CD
//! publishes the manifest that retires it.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use tracing::info;

use crate::tee::{valid_version, EcKey, KeyName, KeyProvider};

/// A transport key version a manifest lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub kid: String,
    /// The version to release it by; absent for versions a worker can only
    /// hold as its current one.
    pub version: Option<String>,
}

pub struct TransportKeys {
    current: Arc<EcKey>,
    current_kid: String,
    /// Other listed versions, by `kid`.
    others: RwLock<BTreeMap<String, Arc<EcKey>>>,
    provider: Arc<dyn KeyProvider>,
}

impl TransportKeys {
    /// `current`, and other versions released from `provider` as manifests
    /// list them.
    pub fn new(current: EcKey, provider: Arc<dyn KeyProvider>) -> Self {
        Self {
            current_kid: current.thumbprint(),
            current: Arc::new(current),
            others: RwLock::new(BTreeMap::new()),
            provider,
        }
    }

    pub fn current_kid(&self) -> &str {
        &self.current_kid
    }

    /// The version `kid` names, if uploads sealed to it open.
    pub fn get(&self, kid: &str) -> Option<Arc<EcKey>> {
        if kid == self.current_kid {
            return Some(self.current.clone());
        }
        self.others.read().ok()?.get(kid).cloned()
    }

    /// Every accepted `kid`, the current one first.
    pub fn kids(&self) -> Vec<String> {
        let others = self
            .others
            .read()
            .map(|o| o.keys().cloned().collect::<Vec<_>>());
        std::iter::once(self.current_kid.clone())
            .chain(others.unwrap_or_default())
            .collect()
    }

    /// Accept the versions `listed` names besides the current one: release
    /// those not held yet, and drop those no longer listed. Every listed
    /// version is tried; the error names each that couldn't be released.
    pub async fn follow(&self, listed: &[Listed]) -> Result<(), String> {
        let wanted: BTreeMap<&str, &str> = listed
            .iter()
            .filter(|l| l.kid != self.current_kid)
            .filter_map(|l| Some((l.kid.as_str(), l.version.as_deref()?)))
            .collect();
        if let Ok(mut others) = self.others.write() {
            others.retain(|kid, _| {
                let keep = wanted.contains_key(kid.as_str());
                if !keep {
                    info!(kid = %kid, "No longer accepting uploads sealed to a transport key version");
                }
                keep
            });
        }

        let mut errors = Vec::new();
        for (kid, version) in wanted {
            if self.others.read().is_ok_and(|o| o.contains_key(kid)) {
                continue;
            }
            if !valid_version(version) {
                errors.push(format!("{version:?} isn't a key version"));
                continue;
            }
            match self
                .provider
                .release_version(KeyName::Transport, version)
                .await
            {
                Ok(key) if key.thumbprint() == kid => {
                    info!(
                        kid,
                        version, "Accepting uploads sealed to a listed transport key version"
                    );
                    if let Ok(mut others) = self.others.write() {
                        others.insert(kid.to_string(), Arc::new(key));
                    }
                }
                Ok(key) => errors.push(format!(
                    "transport-key version {version} is {}, not the listed {kid}",
                    key.thumbprint()
                )),
                Err(e) => errors.push(format!("releasing transport-key version {version}: {e}")),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tee::tests::{fixed_key, Versions};

    /// Test key 1 as the current version, with versions `v2` (test key 2)
    /// and `v3` (test key 3) to release.
    pub(crate) fn rotating() -> TransportKeys {
        let provider = Versions([("v2", 2), ("v3", 3)].into());
        TransportKeys::new(fixed_key(1), Arc::new(provider))
    }

    pub(crate) fn listed(kid: String, version: Option<&str>) -> Listed {
        Listed {
            kid,
            version: version.map(String::from),
        }
    }

    #[tokio::test]
    async fn follows_the_listed_versions_and_always_keeps_the_current_one() {
        let keys = rotating();
        let (one, two, three) = (
            fixed_key(1).thumbprint(),
            fixed_key(2).thumbprint(),
            fixed_key(3).thumbprint(),
        );
        assert!(keys.get(&one).is_some() && keys.get(&two).is_none());

        keys.follow(&[listed(one.clone(), None), listed(two.clone(), Some("v2"))])
            .await
            .unwrap();
        assert_eq!(keys.kids(), [one.clone(), two.clone()]);
        assert_eq!(
            keys.get(&two).unwrap().public_key(),
            fixed_key(2).public_key()
        );

        // The next manifest retires version 2; the current version stays.
        keys.follow(&[listed(three.clone(), Some("v3"))])
            .await
            .unwrap();
        assert_eq!(keys.kids(), [one.clone(), three.clone()]);
        assert!(keys.get(&two).is_none() && keys.get(&one).is_some());
    }

    #[tokio::test]
    async fn refuses_versions_that_dont_match_their_kid_or_cant_name_one() {
        let keys = rotating();
        let two = fixed_key(2).thumbprint();
        let err = keys
            .follow(&[
                listed(two.clone(), Some("v3")),
                listed("k".into(), Some("../other-key")),
                listed("k2".into(), Some("v9")),
                listed("unreleasable".into(), None),
            ])
            .await
            .unwrap_err();
        assert!(err.contains("not the listed"), "{err}");
        assert!(err.contains("isn't a key version"), "{err}");
        assert!(err.contains("no version v9"), "{err}");
        assert_eq!(keys.kids(), [fixed_key(1).thumbprint()]);
    }
}
