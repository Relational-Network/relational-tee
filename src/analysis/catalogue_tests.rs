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
    scope_key: &'static str,
}

const EXAMPLES: &[Example] = &[
    Example {
        source: crate::analysis::definition::tests::AWARDS_REPORT,
        headers: "Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,Employer,Employer Group,Award,Award Grade,Exam Board Date",
        dates: &["date_of_birth", "exam_board_date"],
        filters: &["award", "exam_board_date", "membership_number", "staff_number"],
        scope_key: "employer_group",
        sort: "exam_board_date",
    },
    Example {
        source: include_str!("../../drt-examples/modules-report-v1.toml"),
        headers: "Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,Employer,Employer Group,Programme Level (NFQ),Programme,Module,Exam Result,Exam Date,Registration Date,Registration Mode,Exam Board Date,Exam Attendance Status (MCC Modules),MCC Module",
        dates: &["date_of_birth", "exam_date", "registration_date", "exam_board_date"],
        filters: &["exam_date", "mcc_module", "membership_number", "module", "programme", "registration_date", "registration_mode", "staff_number"],
        scope_key: "employer_group",
        sort: "registration_date",
    },
    Example {
        source: include_str!("../../drt-examples/mcc-categories-v1.toml"),
        headers: "Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,Employer,Employer Group,Designation,Designation Status,Date Designated,Category Name,Category Type,Category Date Accredited,Shortfall Warning Status",
        dates: &["date_of_birth", "date_designated", "category_date_accredited"],
        filters: &["category_date_accredited", "designation", "membership_number", "staff_number"],
        scope_key: "employer_group",
        sort: "category_date_accredited",
    },
    Example {
        source: include_str!("../../drt-examples/exam-modules-v1.toml"),
        headers: "Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,Employer,Employer Group,Module,Exam Date",
        dates: &["date_of_birth", "exam_date"],
        filters: &["membership_number", "staff_number"],
        scope_key: "employer_group",
        sort: "exam_date",
    },
    Example {
        source: include_str!("../../drt-examples/cpd-report-v1.toml"),
        headers: "Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,Employer,Employer Group,CPD Year,Designation,Designation Status,Last Status Update Date,Date Designated,Pro-rata Applied,Shortfall Applied,Total Hours Required,Total Hours Recorded,Category Name,Category Type,Category Date Accredited,Category Hours Required,Category Hours Recorded,Annual Return Made,Total Hours Returned,Category Hours Returned,Total Shortfall,Category Shortfall,Audited,Shortfall Warning Status,Shortfall Warning Start Date,Shortfall Warning End Date,Last Shortfall Warning Removal Date,Reason for Last Shortfall Removal",
        dates: &["date_of_birth", "last_status_update_date", "date_designated", "category_date_accredited", "shortfall_warning_start_date", "shortfall_warning_end_date", "last_shortfall_warning_removal_date"],
        filters: &["cpd_year", "designation", "designation_status", "membership_number", "staff_number"],
        scope_key: "employer_group",
        sort: "cpd_year",
    },
    Example {
        source: include_str!("../../drt-examples/designation-status-v1.toml"),
        headers: "Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,Employer,Employer Group,Designation,Current Status,Previous Status,Status Update Date,Reason for Change",
        dates: &["date_of_birth", "status_update_date"],
        filters: &["current_status", "designation", "membership_number", "previous_status", "reason_for_change", "staff_number", "status_update_date"],
        scope_key: "employer_group",
        sort: "status_update_date",
    },
    Example {
        source: include_str!("../../drt-examples/cpd-audit-v1.toml"),
        headers: "Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,Employer,Employer Group,Audit Year,Designation,Designation Status,Audit Receipt Date,Audit Outcome",
        dates: &["date_of_birth", "audit_receipt_date"],
        filters: &["audit_outcome", "audit_year", "membership_number", "staff_number"],
        scope_key: "employer_group",
        sort: "audit_year",
    },
    Example {
        source: include_str!("../../drt-examples/orders-report-v1.toml"),
        headers: "Order Date,Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,Order Type,Item Description,Item Category,Fee Payment Facility Details,Fee Payment Facility Code,Order ID,Authorisation Code,Item Fee",
        dates: &["date_of_birth", "order_date"],
        filters: &["fee_payment_facility_code", "item_category", "membership_number", "order_date", "order_type", "staff_number"],
        sort: "order_date",
        scope_key: "fee_payment_facility_code",
    },
 ];

impl Example {
    fn scope(&self) -> Scope {
        if self.scope_key == "fee_payment_facility_code" {
            only(&[
                &[(self.scope_key, "Value A")],
                &[(self.scope_key, "Value B")],
            ])
        } else {
            groups(&["Group A"])
        }
    }
}

/// Five invented rows: one blank, two tied dates, repeated identifiers and
/// one row outside Group A. No export data is included in the tests.
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
                "staff_number" => ["000123", "", "000123", "009999", "000124"][i],
                "membership_number" => ["001", "", "001", "099", "002"][i],
                "fee_payment_facility_code" => {
                    ["Value A", "Value A", "Value B", "Secret", "Value A"][i]
                }
                "order_id" => ["00001", "00002", "00003", "00004", "00005"][i],
                "authorisation_code" => ["001A", "002A", "003A", "004A", "005A"][i],
                "item_fee" => ["-25.00", "0.00", "25.00", "50.00", "-10.00"][i],
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
/// Every catalogue definition keeps its schema, scope and filter contract.
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
            if example.scope_key == "fee_payment_facility_code" {
                BTreeMap::from([(
                    "fee_payment_facility_code".into(),
                    "fee_payment_facility_code".into(),
                )])
            } else {
                BTreeMap::from([
                    ("employer".into(), "employer".into()),
                    ("employer_group".into(), "employer_group".into()),
                ])
            }
        );
        assert!(def.schema().iter().all(|c| c.nullable));
    }
}

#[test]
/// Generated pages and counts match the pinned reference SQL for every view.
fn catalogue_pages_match_reference_sql_with_blanks_dates_and_every_sort() {
    for example in EXAMPLES {
        let def = Definition::parse(example.source.as_bytes()).unwrap();
        let csv = data(&def);
        for scope in [Scope::All, example.scope()] {
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
                        serde_json::json!({"mode":"selected","values":[""]}),
                        serde_json::json!({"mode":"selected","values":["", if filter.name == "staff_number" {"000123"} else {"001"}]}),
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
/// Scope and blank selections constrain all derived views of a dataset.
fn catalogue_scopes_restrict_rows_options_searches_and_member_counts() {
    for example in EXAMPLES {
        let def = Definition::parse(example.source.as_bytes()).unwrap();
        let csv = data(&def);
        let table = build(&def, &[&csv], &example.scope());
        let query = Query::check(
            &def,
            &request(serde_json::json!({"distinct":["membership_number"]})),
        )
        .unwrap();
        let page = table.page(&def, &query, &soon()).unwrap();
        assert_eq!(page.total_matched, 4);
        assert_eq!(page.distinct["membership_number"], 2);
        assert!(page
            .rows
            .iter()
            .all(|r| r[example.scope_key] != "Secret" && r[example.scope_key] != "Group B"));
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
        assert_eq!(
            build(&def, &[&csv], &only(&[&[(example.scope_key, "Missing")]])).rows,
            0
        );
        for filter in def
            .filters
            .iter()
            .filter(|f| f.kind == FilterKind::MultiSelect && f.name != "fee_payment_facility_code")
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
                    == [""]
            );
            for other in def.filters.iter().filter(|f| {
                f.kind == FilterKind::MultiSelect
                    && f.name != filter.name
                    && f.name != "fee_payment_facility_code"
            }) {
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
        for (field, populated, hidden) in [
            ("staff_number", "000123", "009999"),
            ("membership_number", "001", "099"),
        ] {
            let steps = plan(&table, def.options_sql(field).unwrap());
            assert!(
                steps.contains(&format!("INDEX _exact_{field}")),
                "{field}: {steps}"
            );
            assert!(!steps.contains("TEMP B-TREE"), "{field}: {steps}");
            let found = table.search(&def, field, "", 20, &query, &soon()).unwrap();
            assert_eq!(found.first().map(String::as_str), Some(""));
            assert!(!found.iter().any(|value| value == hidden));
            for (values, expected) in [
                (vec![""], 1),
                (vec!["", populated], 3),
                (vec!["", hidden], 1),
            ] {
                let selected = Query::check(
                    &def,
                    &request(serde_json::json!({
                        "filters": {field: {"mode":"selected", "values":values}},
                        "distinct": ["membership_number"],
                    })),
                )
                .unwrap();
                let page = table.page(&def, &selected, &soon()).unwrap();
                assert_eq!(page.total_matched, expected);
                assert_eq!(page.distinct["membership_number"], u64::from(expected > 1));
                // A search keeps its own alternatives available.
                assert_eq!(
                    table
                        .search(&def, field, "", 20, &selected, &soon())
                        .unwrap(),
                    found
                );
            }
        }
    }
}

#[test]
fn orders_facility_filters_intersect_grants_and_never_reveal_other_codes() {
    let def =
        Definition::parse(include_bytes!("../../drt-examples/orders-report-v1.toml")).unwrap();
    let mut csv = String::from_utf8(data(&def)).unwrap();
    // A row without a facility is available to admins, never a named-code grant.
    csv.push_str("01/04/2026,008888,088,Mx,Alex,Alpha,,Value A,Subject A,Value A,Facility details,,00006,000A,-12.50\n");
    let key = "fee_payment_facility_code";
    let targets = ["Value A", "Value B"].map(|value| Target {
        key: key.into(),
        value: value.into(),
    });
    let allowed = Scope::of(&check_targets(&def, &targets).unwrap());
    assert!(check_targets(
        &def,
        &[Target {
            key: "employer".into(),
            value: "Bank A".into()
        }]
    )
    .is_err());
    assert!(check_targets(
        &def,
        &[Target {
            key: key.into(),
            value: "".into()
        }]
    )
    .is_err());
    let counts =
        crate::analysis::table::ScopeCounts::count(&def, &[csv.as_bytes()], &soon()).unwrap();
    assert_eq!(counts.keys, [key]);
    assert_eq!(counts.rows(), 6);
    let (visible, hidden) = counts.split(&allowed);
    assert_eq!(visible.iter().map(|c| c.rows).sum::<u64>(), 4);
    assert_eq!(hidden.iter().map(|c| c.rows).sum::<u64>(), 2);
    let open = Query::check(
        &def,
        &request(serde_json::json!({"distinct":["membership_number"]})),
    )
    .unwrap();
    for (scope, rows, members, secret, blank, mixed) in [
        (Scope::All, 6, 4, 1, 1, 5),
        (allowed.clone(), 4, 2, 0, 0, 3),
        (only(&[&[(key, "Value A")]]), 3, 2, 0, 0, 3),
        (only(&[&[(key, "Missing")]]), 0, 0, 0, 0, 0),
    ] {
        let table = build(&def, &[csv.as_bytes()], &scope);
        let page = table.page(&def, &open, &soon()).unwrap();
        assert_eq!(page.total_matched, rows);
        assert_eq!(page.distinct["membership_number"], members);
        for (values, expected) in [
            (vec!["Secret"], secret),
            (vec![""], blank),
            (vec!["", "Value A", "Secret"], mixed),
        ] {
            let query = Query::check(
                &def,
                &request(serde_json::json!({
                    "filters":{key:{"mode":"selected","values":values}},
                    "distinct":["membership_number"]
                })),
            )
            .unwrap();
            let page = table.page(&def, &query, &soon()).unwrap();
            assert_eq!(page.total_matched, expected);
            let mut reference = wrapped(&table, &def, &query);
            let members = reference
                .rows
                .iter()
                .filter_map(|row| row["membership_number"].as_str())
                .filter(|value| !value.is_empty())
                .collect::<std::collections::BTreeSet<_>>()
                .len() as u64;
            reference
                .distinct
                .insert("membership_number".into(), members);
            assert_eq!(page, reference);
            // Dropping a facet's own filter keeps the grant's restriction.
            assert_eq!(
                table.facets(&def, &query, &soon()).unwrap()[key],
                table.options()[key]
            );
        }
    }
    let table = build(&def, &[csv.as_bytes()], &allowed);
    let codes = FilterOptions::Values(vec![
        OptionValue {
            value: "Value A".into(),
            count: 3,
        },
        OptionValue {
            value: "Value B".into(),
            count: 1,
        },
    ]);
    assert_eq!(table.options()[key], codes);
    let hidden = Query::check(
        &def,
        &request(serde_json::json!({
            "filters":{key:{"mode":"selected","values":["Secret"]}},
            "distinct":["membership_number"]
        })),
    )
    .unwrap();
    let page = table.page(&def, &hidden, &soon()).unwrap();
    assert_eq!(page.distinct["membership_number"], 0);
    for field in ["staff_number", "membership_number"] {
        assert!(table
            .search(&def, field, "", 20, &hidden, &soon())
            .unwrap()
            .is_empty());
    }
    assert_eq!(
        table.facets(&def, &hidden, &soon()).unwrap()["item_category"],
        FilterOptions::Values(vec![])
    );
    let date = Query::check(
        &def,
        &request(serde_json::json!({
            "filters":{"order_date":{"from":"01/01/2026","to":"01/01/2026"}},
            "distinct":["membership_number"]
        })),
    )
    .unwrap();
    let page = table.page(&def, &date, &soon()).unwrap();
    assert_eq!(page.total_matched, 2);
    assert_eq!(page.distinct["membership_number"], 2);
    assert_eq!(
        table.facets(&def, &date, &soon()).unwrap()[key],
        FilterOptions::Values(vec![OptionValue {
            value: "Value A".into(),
            count: 2
        }])
    );
    assert_eq!(
        table
            .search(&def, "staff_number", "", 20, &date, &soon())
            .unwrap(),
        ["000123", "000124"]
    );
    assert!(page.rows.iter().any(|r| r["order_id"] == "00001"
        && r["authorisation_code"] == "001A"
        && r["item_fee"] == "-25.00"));
}

#[tokio::test]
/// Every catalogue definition can be fetched, checked and registered as a pool.
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
