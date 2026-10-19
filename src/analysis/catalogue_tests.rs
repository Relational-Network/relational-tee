// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

use super::*;
use std::sync::Arc;

struct Example {
    source: &'static str,
    headers: &'static str,
    dates: &'static [&'static str],
    filters: &'static [&'static str],
    sort: &'static str,
}

const EXAMPLES: &[Example] = &[
    Example {
        source: include_str!("../../drt-examples/modules-report-v1.toml"),
        headers: "Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,Employer,Employer Group,Programme Level (NFQ),Programme,Module,Exam Result,Exam Date,Registration Date,Registration Mode,Exam Board Date,Exam Attendance Status (MCC Modules),MCC Module",
        dates: &["date_of_birth", "exam_date", "registration_date", "exam_board_date"],
        filters: &["exam_date", "mcc_module", "membership_number", "module", "programme", "registration_date", "registration_mode", "staff_number"],
        sort: "registration_date",
    },
    Example {
        source: include_str!("../../drt-examples/mcc-categories-v1.toml"),
        headers: "Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,Employer,Employer Group,Designation,Designation Status,Date Designated,Category Name,Category Type,Category Date Accredited,Shortfall Warning Status",
        dates: &["date_of_birth", "date_designated", "category_date_accredited"],
        filters: &["category_date_accredited", "designation", "membership_number", "staff_number"],
        sort: "category_date_accredited",
    },
    Example {
        source: include_str!("../../drt-examples/exam-modules-v1.toml"),
        headers: "Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,Employer,Employer Group,Module,Exam Date",
        dates: &["date_of_birth", "exam_date"],
        filters: &["membership_number", "staff_number"],
        sort: "exam_date",
    },
    Example {
        source: include_str!("../../drt-examples/cpd-report-v1.toml"),
        headers: "Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,Employer,Employer Group,CPD Year,Designation,Designation Status,Last Status Update Date,Date Designated,Pro-rata Applied,Shortfall Applied,Total Hours Required,Total Hours Recorded,Category Name,Category Type,Category Date Accredited,Category Hours Required,Category Hours Recorded,Annual Return Made,Total Hours Returned,Category Hours Returned,Total Shortfall,Category Shortfall,Audited,Shortfall Warning Status,Shortfall Warning Start Date,Shortfall Warning End Date,Last Shortfall Warning Removal Date,Reason for Last Shortfall Removal",
        dates: &["date_of_birth", "last_status_update_date", "date_designated", "category_date_accredited", "shortfall_warning_start_date", "shortfall_warning_end_date", "last_shortfall_warning_removal_date"],
        filters: &["cpd_year", "designation", "designation_status", "membership_number", "staff_number"],
        sort: "cpd_year",
    },
    Example {
        source: include_str!("../../drt-examples/designation-status-v1.toml"),
        headers: "Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,Employer,Employer Group,Designation,Current Status,Previous Status,Status Update Date,Reason for Change",
        dates: &["date_of_birth", "status_update_date"],
        filters: &["current_status", "designation", "membership_number", "previous_status", "reason_for_change", "staff_number", "status_update_date"],
        sort: "status_update_date",
    },
    Example {
        source: include_str!("../../drt-examples/cpd-audit-v1.toml"),
        headers: "Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,Employer,Employer Group,Audit Year,Designation,Designation Status,Audit Receipt Date,Audit Outcome",
        dates: &["date_of_birth", "audit_receipt_date"],
        filters: &["audit_outcome", "audit_year", "membership_number", "staff_number"],
        sort: "audit_year",
    },
 ];

// Five invented rows: one blank, two tied dates, repeated identifiers and
// one row outside Group A. No export data is included in the tests.
fn data(def: &Definition) -> Vec<u8> {
    let mut csv = def
        .columns
        .iter()
        .map(|c| c.header.as_str())
        .collect::<Vec<_>>()
        .join(",");
    csv.push('\n');
    for i in 0..5 {
        let row = def
            .columns
            .iter()
            .map(|c| match c.name.as_str() {
                "staff_number" => ["000123", "000123", "000123", "009999", "000124"][i],
                "membership_number" => ["001", "", "001", "099", "002"][i],
                "employer" => {
                    if i == 3 {
                        "Bank B"
                    } else {
                        "Bank A"
                    }
                }
                "employer_group" => {
                    if i == 3 {
                        "Group B"
                    } else {
                        "Group A"
                    }
                }
                _ if c.kind == ColumnType::Date => {
                    ["01/01/2026", "", "01/02/2026", "01/03/2026", "01/01/2026"][i]
                }
                _ => ["Value A", "", "Value B", "Secret", "Value A"][i],
            })
            .collect::<Vec<_>>()
            .join(",");
        csv.push_str(&row);
        csv.push('\n');
    }
    csv.into_bytes()
}

#[test]
fn catalogue_schemas_match_the_exports_and_filter_contracts() {
    for example in EXAMPLES {
        let def = Definition::parse(example.source.as_bytes()).unwrap();
        assert_eq!(
            def.columns
                .iter()
                .map(|c| c.header.as_str())
                .collect::<Vec<_>>()
                .join(","),
            example.headers
        );
        assert_eq!(
            def.output,
            def.columns
                .iter()
                .map(|c| c.name.clone())
                .collect::<Vec<_>>()
        );
        for c in &def.columns {
            assert_eq!(
                c.kind == ColumnType::Date,
                example.dates.contains(&c.name.as_str())
            );
        }
        assert_eq!(
            def.filters
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            example.filters
        );
        assert_eq!(def.default_sort, (example.sort.into(), Direction::Desc));
        assert_eq!((def.page_default, def.page_max), (100, 500));
        assert_eq!(
            def.scope,
            BTreeMap::from([
                ("employer".into(), "employer".into()),
                ("employer_group".into(), "employer_group".into())
            ])
        );
        assert!(def.schema().iter().all(|c| c.nullable));
    }
}

#[test]
fn catalogue_pages_match_reference_sql_with_blanks_dates_and_every_sort() {
    for example in EXAMPLES {
        let def = Definition::parse(example.source.as_bytes()).unwrap();
        let csv = data(&def);
        for scope in [Scope::All, groups(&["Group A"])] {
            let table = build(&def, &[&csv], &scope);
            let mut cases = vec![
                serde_json::json!({}),
                serde_json::json!({"pagination": {"limit": 2, "offset": 1}}),
            ];
            let mut combined = serde_json::Map::new();
            for filter in &def.filters {
                let selections = match filter.kind {
                    FilterKind::MultiSelect => vec![
                        serde_json::json!({"mode":"selected","values":[""]}),
                        serde_json::json!({"mode":"selected","values":["", "Value A"]}),
                        serde_json::json!({"mode":"selected","values":["Value A"]}),
                        serde_json::json!({"mode":"selected","values":["Missing"]}),
                    ],
                    FilterKind::DateRange => vec![
                        serde_json::json!({"from":"01/01/2026","to":"01/01/2026"}),
                        serde_json::json!({"from":"01/02/2026"}),
                        serde_json::json!({"to":"01/01/2026"}),
                    ],
                    FilterKind::SearchSelect => vec![
                        serde_json::json!({"mode":"selected","values":[if filter.name == "staff_number" {"000123"} else {"001"}]}),
                    ],
                };
                combined.insert(filter.name.clone(), selections[0].clone());
                for selection in selections {
                    cases.push(serde_json::json!({"filters": {&filter.name: selection}}));
                }
            }
            cases.push(serde_json::json!({"filters": combined}));
            for field in &def.output {
                for direction in ["asc", "desc"] {
                    cases.push(serde_json::json!({"sort":{"field":field,"direction":direction},"pagination":{"limit":2,"offset":1}}));
                }
            }
            for case in cases {
                let query = Query::check(&def, &request(case.clone())).unwrap();
                let page = table.page(&def, &query, &soon()).unwrap();
                assert_eq!(
                    page,
                    wrapped(&table, &def, &query),
                    "{} {case}",
                    def.analysis_id
                );
                assert_eq!(page, table.page(&def, &query, &soon()).unwrap());
            }
        }
    }
}

#[test]
fn catalogue_scopes_restrict_rows_options_searches_and_member_counts() {
    for example in EXAMPLES {
        let def = Definition::parse(example.source.as_bytes()).unwrap();
        let csv = data(&def);
        let table = build(&def, &[&csv], &groups(&["Group A"]));
        let query = Query::check(
            &def,
            &request(serde_json::json!({"distinct":["membership_number"]})),
        )
        .unwrap();
        let page = table.page(&def, &query, &soon()).unwrap();
        assert_eq!(page.total_matched, 4);
        assert_eq!(page.distinct["membership_number"], 2);
        assert!(page.rows.iter().all(|r| r["employer_group"] == "Group A"));
        assert_eq!(
            table
                .search(&def, "staff_number", "00", 20, &query, &soon())
                .unwrap(),
            ["000123", "000124"]
        );
        assert_eq!(
            table
                .search(&def, "membership_number", "0", 20, &query, &soon())
                .unwrap(),
            ["001", "002"]
        );
        assert_eq!(build(&def, &[&csv], &groups(&["Missing"])).rows, 0);
        for filter in def
            .filters
            .iter()
            .filter(|f| f.kind == FilterKind::MultiSelect)
        {
            let FilterOptions::Values(values) = &table.options()[&filter.name] else {
                panic!("select options")
            };
            assert_eq!(
                values
                    .iter()
                    .map(|v| (v.value.as_str(), v.count))
                    .collect::<Vec<_>>(),
                [("", 1), ("Value A", 2), ("Value B", 1)]
            );
            let blank = Query::check(&def, &request(serde_json::json!({"filters": {&filter.name: {"mode":"selected","values":[""]}}, "distinct":["membership_number"]}))).unwrap();
            let page = table.page(&def, &blank, &soon()).unwrap();
            assert_eq!(page.total_matched, 1);
            assert_eq!(page.distinct["membership_number"], 0);
            assert!(
                table
                    .search(&def, "staff_number", "", 20, &blank, &soon())
                    .unwrap()
                    == ["000123"]
            );
            for other in def
                .filters
                .iter()
                .filter(|f| f.kind == FilterKind::MultiSelect && f.name != filter.name)
            {
                let facets = table.facets(&def, &blank, &soon()).unwrap();
                assert_eq!(
                    facets[&other.name],
                    FilterOptions::Values(vec![OptionValue {
                        value: "".into(),
                        count: 1
                    }])
                );
            }
            // A nonblank selection keeps the index-friendly condition.
            let normal = Query::check(&def, &request(serde_json::json!({"filters": {&filter.name: {"mode":"selected","values":["Value A"]}}}))).unwrap();
            assert!(!normal.conditions().0.contains("IS NULL"));
        }
        assert!(Query::check(
            &def,
            &request(
                serde_json::json!({"filters":{"staff_number":{"mode":"selected","values":[""]}}})
            )
        )
        .is_err());
    }
}

#[tokio::test]
async fn catalogue_definitions_create_pools_through_the_checked_fetcher() {
    use crate::analysis::fetch::tests::Fixed;
    use crate::api::credentials::tests::{send, worker_with};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use std::sync::atomic::Ordering::SeqCst;
    for example in EXAMPLES {
        let def = Definition::parse(example.source.as_bytes()).unwrap();
        let url = format!("https://raw.githubusercontent.com/relational-network/relational-tee/0123456789abcdef0123456789abcdef01234567/drt-examples/{}.toml", def.analysis_id);
        let fixed = Arc::new(Fixed {
            files: BTreeMap::from([(url.clone(), example.source.as_bytes().to_vec())]),
            ..Fixed::default()
        });
        let worker = worker_with(|state| state.fetcher = fixed.clone());
        worker.chain.lands.store(true, SeqCst);
        let owner = worker.admin("oid-owner").await;
        let body = serde_json::json!({"wallet_id":owner.wallet_id,"pool_name":def.display_name,"append_supply":1000,"analysis":{"code_repo_url":url,"code_hash_hex":hex::encode(def.sha256),"supply":200}});
        let req = Request::post("/v1/drt/pools/malta")
            .header("Authorization", format!("Bearer {}", owner.token))
            .header("Idempotency-Key", uuid::Uuid::new_v4().to_string())
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _, response) = send(&worker.app, req).await;
        assert_eq!(status, StatusCode::CREATED, "{response}");
        assert_eq!(fixed.fetched.lock().unwrap().as_slice(), [url]);
    }
}
