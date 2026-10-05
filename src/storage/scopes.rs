// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The employer-scope mapping: which rows of an analysis the members of each
//! Entra security group may see. One sealed document,
//! `config/employer-scopes.json`, which admins replace whole. Its `version`
//! goes up by one with each replacement, and a replacement names the version
//! it was edited from, so an edit made from a stale copy is refused.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{Storage, StoreError};
use crate::analysis::table::Scope;
use crate::store::{Created, Replaced};

const PATH: &str = "config/employer-scopes.json";

/// The most entries a mapping holds.
pub const MAX_SCOPES: usize = 1000;

/// The longest group ID, label or employer name, in bytes.
const MAX_TEXT: usize = 256;

/// The rows one group's members may see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EmployerScope {
    /// The group as the token's `groups` claim names it: its object ID.
    pub group_id: String,
    /// The group's name, for people, such as `UAT_EDQ_CP_AIB`.
    pub label: String,
    /// Rows whose employer group is exactly this. Set this or `employer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub employer_group: Option<String>,
    /// Rows whose employer is exactly this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub employer: Option<String>,
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
    /// The rows members of `groups` may see: every scope mapped to any of
    /// them. `None` if none of them is mapped.
    pub fn rows_for(&self, groups: &[String]) -> Option<Scope> {
        let mut employer_groups = BTreeSet::new();
        let mut employers = BTreeSet::new();
        for scope in self.scopes.iter().filter(|s| groups.contains(&s.group_id)) {
            employer_groups.extend(scope.employer_group.clone());
            employers.extend(scope.employer.clone());
        }
        (!employer_groups.is_empty() || !employers.is_empty()).then_some(Scope::Only {
            employer_groups,
            employers,
        })
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
        match (&scope.employer_group, &scope.employer) {
            (Some(group), None) => check_text(&format!("scopes[{i}].employer_group"), group)?,
            (None, Some(employer)) => check_text(&format!("scopes[{i}].employer"), employer)?,
            _ => {
                return Err(format!(
                    "scopes[{i}] needs exactly one of employer_group and employer"
                ))
            }
        }
        if !seen.insert((&scope.group_id, &scope.employer_group, &scope.employer)) {
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
                return Ok(Some(current));
            }
            if current.version != version {
                return Ok(None);
            }
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
                return Ok(Some(next));
            }
        }
        Err(StoreError::Contended)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::storage::tests::two_workers;

    pub(crate) const AIB_GROUP: &str = "3f0c5a6e-0000-4000-8000-00000000a1b0";
    pub(crate) const EBS_GROUP: &str = "3f0c5a6e-0000-4000-8000-00000000eb50";

    /// The test fixture: `UAT_EDQ_CP_AIB` sees employer group AIB, and
    /// `UAT_EDQ_EBS_NETWORK` sees employer EBS Network.
    pub(crate) fn fixture() -> Vec<EmployerScope> {
        vec![
            EmployerScope {
                group_id: AIB_GROUP.into(),
                label: "UAT_EDQ_CP_AIB".into(),
                employer_group: Some("AIB".into()),
                employer: None,
            },
            EmployerScope {
                group_id: EBS_GROUP.into(),
                label: "UAT_EDQ_EBS_NETWORK".into(),
                employer_group: None,
                employer: Some("EBS Network".into()),
            },
        ]
    }

    fn only(groups: &[&str], employers: &[&str]) -> Option<Scope> {
        Some(Scope::Only {
            employer_groups: groups.iter().map(|g| g.to_string()).collect(),
            employers: employers.iter().map(|e| e.to_string()).collect(),
        })
    }

    #[test]
    fn groups_resolve_to_the_union_of_their_scopes() {
        let mapping = EmployerScopes {
            scopes: fixture(),
            ..Default::default()
        };
        let groups = |list: &[&str]| list.iter().map(|g| g.to_string()).collect::<Vec<_>>();
        assert_eq!(mapping.rows_for(&groups(&[AIB_GROUP])), only(&["AIB"], &[]));
        assert_eq!(
            mapping.rows_for(&groups(&["unmapped", EBS_GROUP])),
            only(&[], &["EBS Network"])
        );
        assert_eq!(
            mapping.rows_for(&groups(&[EBS_GROUP, AIB_GROUP])),
            only(&["AIB"], &["EBS Network"])
        );
        assert_eq!(mapping.rows_for(&groups(&["unmapped"])), None);
        assert_eq!(mapping.rows_for(&[]), None);
        assert_eq!(
            EmployerScopes::default().rows_for(&groups(&[AIB_GROUP])),
            None
        );
    }

    #[test]
    fn a_mapping_names_one_target_per_entry_exactly() {
        assert_eq!(check(&fixture()), Ok(()));
        assert_eq!(check(&[]), Ok(()));
        let spoiled = |spoil: fn(&mut EmployerScope)| {
            let mut scopes = fixture();
            spoil(&mut scopes[1]);
            check(&scopes)
        };
        assert!(spoiled(|s| s.employer_group = Some("AIB".into())).is_err());
        assert!(spoiled(|s| s.employer = None).is_err());
        assert!(spoiled(|s| s.employer = Some(" EBS Network".into())).is_err());
        assert!(spoiled(|s| s.employer = Some(String::new())).is_err());
        assert!(spoiled(|s| s.group_id = "a\nb".into()).is_err());
        assert!(spoiled(|s| s.label = "x".repeat(MAX_TEXT + 1)).is_err());
        let mut repeated = fixture();
        repeated.push(repeated[0].clone());
        assert!(check(&repeated).is_err());

        // A group may see more than one employer.
        let mut both = fixture();
        both.push(EmployerScope {
            employer_group: None,
            employer: Some("EBS Network".into()),
            ..both[0].clone()
        });
        assert_eq!(check(&both), Ok(()));
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
        let aib_only = fixture()[..1].to_vec();
        assert_eq!(
            b.employer_scopes()
                .replace(0, aib_only.clone(), "admin-2")
                .await
                .unwrap(),
            None
        );
        let second = b
            .employer_scopes()
            .replace(1, aib_only.clone(), "admin-2")
            .await
            .unwrap()
            .unwrap();
        assert_eq!((second.version, second.scopes), (2, aib_only));
    }

    #[tokio::test]
    async fn of_two_concurrent_edits_from_one_version_one_lands() {
        let (a, b, _files) = two_workers();
        let aib_only = fixture()[..1].to_vec();
        let (scopes_a, scopes_b) = (a.employer_scopes(), b.employer_scopes());
        let (x, y) = tokio::join!(
            scopes_a.replace(0, fixture(), "admin-1"),
            scopes_b.replace(0, aib_only, "admin-2"),
        );
        let landed: Vec<_> = [x.unwrap(), y.unwrap()].into_iter().flatten().collect();
        assert_eq!(landed.len(), 1, "{landed:?}");
        assert_eq!(a.employer_scopes().get().await.unwrap(), landed[0]);
    }
}
