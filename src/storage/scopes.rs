// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The employer-scope mapping: which rows of an analysis the members of each
//! Entra security group may see. One sealed document,
//! `config/employer-scopes.json`, which admins replace whole. Its `version`
//! goes up by one with each replacement, and a replacement names the version
//! it was edited from, so an edit made from a stale copy is refused.
//!
//! Every version is also kept, create-only, under
//! `config/employer-scope-versions/`. A replacement records the version it
//! makes, and first the one it replaces if that isn't recorded yet, so a
//! version whose record failed is recorded before it stops being current.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{Storage, StoreError};
use crate::analysis::definition::is_sql_name;
use crate::analysis::table::{Conditions, Scope};
use crate::store::{Created, Replaced};

const PATH: &str = "config/employer-scopes.json";
const VERSIONS: &str = "config/employer-scope-versions/";

/// Where a version is kept: zero-padded, so name order is version order.
fn version_path(version: u64) -> String {
    format!("{VERSIONS}{version:012}.json")
}

/// The most entries a mapping holds.
pub const MAX_SCOPES: usize = 1000;

/// The most conditions one entry holds.
pub const MAX_CONDITIONS: usize = 8;

/// The longest group ID, label or value, in bytes.
const MAX_TEXT: usize = 256;

/// The rows one group's members may see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EmployerScope {
    /// The group as the token's `groups` claim names it: its object ID.
    pub group_id: String,
    /// The group's name, for people, such as `GROUP_A_ANALYSTS`.
    pub label: String,
    /// Every other field is a condition: a scope key analyses declare, such
    /// as `employer_group` or `employer`, and the value a row's column for
    /// it must hold exactly. The entry grants the rows that meet them all.
    #[serde(flatten)]
    #[schema(inline)]
    pub conditions: Conditions,
}

/// The whole mapping.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EmployerScopes {
    /// 0 until the first replacement.
    pub version: u64,
    pub scopes: Vec<EmployerScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    /// The `user_id` of the admin who last replaced it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
}

impl EmployerScopes {
    /// The rows members of `groups` may see: those of every entry mapped to
    /// any of them. `None` if none of them is mapped.
    pub fn rows_for(&self, groups: &[String]) -> Option<Scope> {
        let entries: BTreeSet<Conditions> = self
            .scopes
            .iter()
            .filter(|s| groups.contains(&s.group_id))
            .map(|s| s.conditions.clone())
            .collect();
        (!entries.is_empty()).then_some(Scope::Only(entries))
    }
}

fn check_text(what: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_TEXT
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{what} must be 1 to {MAX_TEXT} bytes, with no surrounding spaces or control characters"
        ));
    }
    Ok(())
}

/// Why `scopes` can't be the mapping, if it can't. Names are compared
/// exactly, as the data holds them, so they must not carry stray spaces.
pub fn check(scopes: &[EmployerScope]) -> Result<(), String> {
    if scopes.len() > MAX_SCOPES {
        return Err(format!("a mapping holds at most {MAX_SCOPES} entries"));
    }
    let mut seen = BTreeSet::new();
    for (i, scope) in scopes.iter().enumerate() {
        check_text(&format!("scopes[{i}].group_id"), &scope.group_id)?;
        check_text(&format!("scopes[{i}].label"), &scope.label)?;
        if scope.conditions.is_empty() || scope.conditions.len() > MAX_CONDITIONS {
            return Err(format!(
                "scopes[{i}] needs 1 to {MAX_CONDITIONS} conditions, such as \"employer_group\": \"Group A\""
            ));
        }
        for (key, value) in &scope.conditions {
            if !is_sql_name(key) {
                return Err(format!(
                    "scopes[{i}].{key:?} isn't a scope key: lowercase letters, digits and underscores"
                ));
            }
            check_text(&format!("scopes[{i}].{key}"), value)?;
        }
        if !seen.insert((&scope.group_id, &scope.conditions)) {
            return Err(format!("scopes[{i}] repeats an earlier entry"));
        }
    }
    Ok(())
}

/// Employer-scope storage.
pub struct Scopes<'a> {
    s: &'a Storage,
}

impl<'a> Scopes<'a> {
    pub(crate) fn new(s: &'a Storage) -> Self {
        Self { s }
    }

    /// The current mapping: empty, at version 0, until the first replacement.
    pub async fn get(&self) -> Result<EmployerScopes, StoreError> {
        Ok(self
            .s
            .state()
            .get_json(PATH)
            .await?
            .map(|(mapping, _)| mapping)
            .unwrap_or_default())
    }

    /// Replace the mapping with `scopes`, as `user_id`, if it's still at
    /// `version`, and return the new mapping. A mapping that already holds
    /// `scopes` is returned as it is, so a retry converges; `None` means
    /// another replacement came first.
    pub async fn replace(
        &self,
        version: u64,
        scopes: Vec<EmployerScope>,
        user_id: &str,
    ) -> Result<Option<EmployerScopes>, StoreError> {
        let state = self.s.state();
        // A lost race moves the version on, so the second pass returns.
        for _ in 0..2 {
            let (current, etag) = match state.get_json::<EmployerScopes>(PATH).await? {
                Some((mapping, etag)) => (mapping, Some(etag)),
                None => (EmployerScopes::default(), None),
            };
            if current.scopes == scopes {
                self.record(&current).await?;
                return Ok(Some(current));
            }
            if current.version != version {
                return Ok(None);
            }
            self.record(&current).await?;
            let next = EmployerScopes {
                version: version + 1,
                scopes: scopes.clone(),
                updated_at: Some(Utc::now()),
                updated_by: Some(user_id.to_string()),
            };
            let written = match etag {
                None => matches!(state.create_json(PATH, &next).await?, Created::New(_)),
                Some(etag) => matches!(
                    state.replace_json(PATH, &next, &etag).await?,
                    Replaced::Done(_)
                ),
            };
            if written {
                self.record(&next).await?;
                return Ok(Some(next));
            }
        }
        Err(StoreError::Contended)
    }

    /// Keep `mapping` as its version, unless it's kept already. A version
    /// number names one mapping only, since only one replacement can make it.
    async fn record(&self, mapping: &EmployerScopes) -> Result<(), StoreError> {
        if mapping.version > 0 {
            self.s
                .state()
                .create_json(&version_path(mapping.version), mapping)
                .await?;
        }
        Ok(())
    }

    /// Every version there has been, newest first, the current one included
    /// even if its record is missing.
    pub async fn versions(&self) -> Result<Vec<u64>, StoreError> {
        let mut versions: Vec<u64> = self
            .s
            .state()
            .list(VERSIONS)
            .await?
            .iter()
            .filter_map(|listed| {
                listed
                    .path
                    .strip_prefix(VERSIONS)?
                    .strip_suffix(".json")?
                    .parse()
                    .ok()
            })
            .collect();
        let current = self.get().await?.version;
        if current > 0 && !versions.contains(&current) {
            versions.push(current);
        }
        versions.sort_unstable_by(|a, b| b.cmp(a));
        Ok(versions)
    }

    /// The mapping as `version` made it.
    pub async fn version(&self, version: u64) -> Result<Option<EmployerScopes>, StoreError> {
        if version == 0 {
            return Ok(None);
        }
        let state = self.s.state();
        if let Some(mapping) = state.get_immutable_json(&version_path(version)).await? {
            return Ok(Some(mapping));
        }
        let current = self.get().await?;
        Ok((current.version == version).then_some(current))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::json;

    use super::*;
    use crate::analysis::table::tests::only;
    use crate::storage::tests::two_workers;

    pub(crate) const GROUP_A_ANALYSTS: &str = "3f0c5a6e-0000-4000-8000-00000000000a";
    pub(crate) const NETWORK_ANALYSTS: &str = "3f0c5a6e-0000-4000-8000-00000000000b";

    /// An entry for `group_id` with these conditions.
    pub(crate) fn entry(group_id: &str, label: &str, conditions: &[(&str, &str)]) -> EmployerScope {
        EmployerScope {
            group_id: group_id.into(),
            label: label.into(),
            conditions: conditions
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
        }
    }

    /// The test fixture: `GROUP_A_ANALYSTS` see employer group Group A, and
    /// `NETWORK_ANALYSTS` see employer Bank A Network.
    pub(crate) fn fixture() -> Vec<EmployerScope> {
        vec![
            entry(
                GROUP_A_ANALYSTS,
                "GROUP_A_ANALYSTS",
                &[("employer_group", "Group A")],
            ),
            entry(
                NETWORK_ANALYSTS,
                "NETWORK_ANALYSTS",
                &[("employer", "Bank A Network")],
            ),
        ]
    }

    #[test]
    fn groups_resolve_to_the_union_of_their_scopes() {
        let mapping = EmployerScopes {
            scopes: fixture(),
            ..Default::default()
        };
        let groups = |list: &[&str]| list.iter().map(|g| g.to_string()).collect::<Vec<_>>();
        assert_eq!(
            mapping.rows_for(&groups(&[GROUP_A_ANALYSTS])),
            Some(only(&[&[("employer_group", "Group A")]]))
        );
        assert_eq!(
            mapping.rows_for(&groups(&["unmapped", NETWORK_ANALYSTS])),
            Some(only(&[&[("employer", "Bank A Network")]]))
        );
        assert_eq!(
            mapping.rows_for(&groups(&[NETWORK_ANALYSTS, GROUP_A_ANALYSTS])),
            Some(only(&[
                &[("employer_group", "Group A")],
                &[("employer", "Bank A Network")]
            ]))
        );
        assert_eq!(mapping.rows_for(&groups(&["unmapped"])), None);
        assert_eq!(mapping.rows_for(&[]), None);
        assert_eq!(
            EmployerScopes::default().rows_for(&groups(&[GROUP_A_ANALYSTS])),
            None
        );
    }

    #[test]
    fn an_entry_keeps_its_conditions_beside_its_group() {
        let stored = json!({
            "group_id": GROUP_A_ANALYSTS,
            "label": "GROUP_A_ANALYSTS",
            "employer_group": "Group A",
        });
        let read: EmployerScope = serde_json::from_value(stored.clone()).unwrap();
        assert_eq!(read, fixture()[0]);
        assert_eq!(serde_json::to_value(&read).unwrap(), stored);
        let not_text = json!({ "group_id": "g", "label": "G", "employer": 1 });
        assert!(serde_json::from_value::<EmployerScope>(not_text).is_err());
    }

    #[test]
    fn an_entry_names_its_conditions_exactly() {
        assert_eq!(check(&fixture()), Ok(()));
        assert_eq!(check(&[]), Ok(()));
        let spoiled = |spoil: fn(&mut EmployerScope)| {
            let mut scopes = fixture();
            spoil(&mut scopes[1]);
            check(&scopes)
        };
        assert!(spoiled(|s| s.conditions.clear()).is_err());
        assert!(spoiled(|s| {
            s.conditions
                .insert("Employer Group".into(), "Group A".into());
        })
        .is_err());
        assert!(spoiled(|s| {
            s.conditions
                .insert("employer".into(), " Bank A Network".into());
        })
        .is_err());
        assert!(spoiled(|s| {
            s.conditions.insert("employer".into(), String::new());
        })
        .is_err());
        assert!(spoiled(|s| {
            s.conditions = (0..=MAX_CONDITIONS)
                .map(|i| (format!("key_{i}"), "v".into()))
                .collect();
        })
        .is_err());
        assert!(spoiled(|s| s.group_id = "a\nb".into()).is_err());
        assert!(spoiled(|s| s.label = "x".repeat(MAX_TEXT + 1)).is_err());
        let mut repeated = fixture();
        repeated.push(repeated[0].clone());
        assert!(check(&repeated).is_err());

        // A group may see several slices, and a slice may need several
        // conditions at once.
        let mut more = fixture();
        more.push(entry(
            GROUP_A_ANALYSTS,
            "GROUP_A_ANALYSTS",
            &[("employer", "Bank A Network")],
        ));
        more.push(entry(
            GROUP_A_ANALYSTS,
            "GROUP_A_ANALYSTS",
            &[("employer_group", "Group C"), ("region", "Region D")],
        ));
        assert_eq!(check(&more), Ok(()));
    }

    #[tokio::test]
    async fn replacements_name_the_version_they_were_edited_from() {
        let (a, b, _files) = two_workers();
        assert_eq!(
            a.employer_scopes().get().await.unwrap(),
            EmployerScopes::default()
        );

        let first = a
            .employer_scopes()
            .replace(0, fixture(), "admin-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.version, 1);
        assert_eq!(first.updated_by.as_deref(), Some("admin-1"));
        assert_eq!(b.employer_scopes().get().await.unwrap(), first);

        // A retry of the same replacement converges on it.
        let again = b
            .employer_scopes()
            .replace(0, fixture(), "admin-1")
            .await
            .unwrap();
        assert_eq!(again, Some(first.clone()));

        // An edit from the stale version 0 is refused; one from 1 lands.
        let group_a_only = fixture()[..1].to_vec();
        assert_eq!(
            b.employer_scopes()
                .replace(0, group_a_only.clone(), "admin-2")
                .await
                .unwrap(),
            None
        );
        let second = b
            .employer_scopes()
            .replace(1, group_a_only.clone(), "admin-2")
            .await
            .unwrap()
            .unwrap();
        assert_eq!((second.version, second.scopes), (2, group_a_only));
    }

    #[tokio::test]
    async fn every_replacement_is_kept_as_a_version() {
        let (a, b, _files) = two_workers();
        assert!(a.employer_scopes().versions().await.unwrap().is_empty());
        assert_eq!(a.employer_scopes().version(0).await.unwrap(), None);

        let first = a
            .employer_scopes()
            .replace(0, fixture(), "admin-1")
            .await
            .unwrap()
            .unwrap();
        let second = b
            .employer_scopes()
            .replace(1, fixture()[..1].to_vec(), "admin-2")
            .await
            .unwrap()
            .unwrap();
        // A retry of a replacement that landed adds no version.
        b.employer_scopes()
            .replace(1, fixture()[..1].to_vec(), "admin-2")
            .await
            .unwrap();
        assert_eq!(a.employer_scopes().versions().await.unwrap(), [2, 1]);
        assert_eq!(a.employer_scopes().version(1).await.unwrap(), Some(first));
        assert_eq!(a.employer_scopes().version(2).await.unwrap(), Some(second));
        assert_eq!(a.employer_scopes().version(3).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_version_whose_record_failed_is_listed_and_recorded_before_it_is_replaced() {
        let (a, _b, _files) = two_workers();
        let first = EmployerScopes {
            version: 1,
            scopes: fixture(),
            updated_at: Some(Utc::now()),
            updated_by: Some("admin-1".into()),
        };
        a.state().create_json(PATH, &first).await.unwrap();
        let scopes = a.employer_scopes();
        assert_eq!(scopes.versions().await.unwrap(), [1]);
        assert_eq!(scopes.version(1).await.unwrap(), Some(first.clone()));

        scopes
            .replace(1, Vec::new(), "admin-2")
            .await
            .unwrap()
            .unwrap();
        let recorded: Option<EmployerScopes> = a
            .state()
            .get_immutable_json(&version_path(1))
            .await
            .unwrap();
        assert_eq!(recorded, Some(first));
        assert_eq!(scopes.versions().await.unwrap(), [2, 1]);
    }

    #[tokio::test]
    async fn of_two_concurrent_edits_from_one_version_one_lands() {
        let (a, b, _files) = two_workers();
        let group_a_only = fixture()[..1].to_vec();
        let (scopes_a, scopes_b) = (a.employer_scopes(), b.employer_scopes());
        let (x, y) = tokio::join!(
            scopes_a.replace(0, fixture(), "admin-1"),
            scopes_b.replace(0, group_a_only, "admin-2"),
        );
        let landed: Vec<_> = [x.unwrap(), y.unwrap()].into_iter().flatten().collect();
        assert_eq!(landed.len(), 1, "{landed:?}");
        assert_eq!(a.employer_scopes().get().await.unwrap(), landed[0]);
    }
}
