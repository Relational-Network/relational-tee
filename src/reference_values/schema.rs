// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Holds `deploy/reference-values.schema.json` to the manifests workers and
//! the dashboard read. The checker implements only the keywords the schema
//! uses, with their JSON Schema meaning, and fails on any other, so no rule
//! passes unchecked.

use chrono::{DateTime, Utc};
use regex::Regex;
use serde_json::{json, Value};

use super::dev::Manifest;
use crate::tee::dev_keys::{generate_missing, key_path, previous_key_path};
use crate::tee::{dev_maa, KeyName};

const SCHEMA: &str = include_str!("../../deploy/reference-values.schema.json");

const COMMIT: &str = "24e2e3513c3f25c9ad4628369cce98c811e3786c";

/// Checks `value`, found at `at`, against `schema`, whose `$ref`s resolve
/// in `root`.
fn check(root: &Value, schema: &Value, value: &Value, at: &str) -> Result<(), String> {
    let Some(rules) = schema.as_object() else {
        return Err(format!("{at}: unsupported schema {schema}"));
    };
    for (keyword, rule) in rules {
        let count = || rule.as_u64().expect("a count") as usize;
        let bound = || rule.as_f64().expect("a number");
        let violation = match keyword.as_str() {
            "$schema" | "title" | "description" | "$defs" | "then" | "else" => None,
            "$ref" => {
                let target = rule
                    .as_str()
                    .and_then(|r| r.strip_prefix("#/$defs/"))
                    .and_then(|name| root["$defs"].get(name))
                    .ok_or_else(|| format!("{at}: unresolved $ref {rule}"))?;
                check(root, target, value, at)?;
                None
            }
            "if" => {
                let branch = match check(root, rule, value, at) {
                    Ok(()) => "then",
                    Err(_) => "else",
                };
                if let Some(branch) = rules.get(branch) {
                    check(root, branch, value, at)?;
                }
                None
            }
            "type" => {
                let matches = match rule.as_str() {
                    Some("object") => value.is_object(),
                    Some("array") => value.is_array(),
                    Some("string") => value.is_string(),
                    Some("integer") => value.is_i64() || value.is_u64(),
                    _ => return Err(format!("{at}: unsupported type {rule}")),
                };
                (!matches).then(|| format!("isn't of type {rule}"))
            }
            "const" => (value != rule).then(|| format!("isn't {rule}")),
            "required" => value.as_object().and_then(|members| {
                rule.as_array()?
                    .iter()
                    .filter_map(Value::as_str)
                    .find(|name| !members.contains_key(*name))
                    .map(|name| format!("lacks {name}"))
            }),
            "properties" => {
                if let (Some(members), Some(properties)) = (value.as_object(), rule.as_object()) {
                    for (name, property) in properties {
                        if let Some(member) = members.get(name) {
                            check(root, property, member, &format!("{at}/{name}"))?;
                        }
                    }
                }
                None
            }
            "additionalProperties" if *rule == false => {
                let known = rules.get("properties").and_then(Value::as_object);
                value.as_object().and_then(|members| {
                    members
                        .keys()
                        .find(|name| !known.is_some_and(|known| known.contains_key(*name)))
                        .map(|name| format!("has an unknown member {name}"))
                })
            }
            "items" => {
                for (i, item) in value.as_array().into_iter().flatten().enumerate() {
                    check(root, rule, item, &format!("{at}/{i}"))?;
                }
                None
            }
            "minItems" => value
                .as_array()
                .filter(|items| items.len() < count())
                .map(|_| format!("has fewer than {rule} items")),
            "minLength" => value
                .as_str()
                .filter(|s| s.chars().count() < count())
                .map(|_| format!("is shorter than {rule}")),
            "minimum" => value
                .as_f64()
                .filter(|n| *n < bound())
                .map(|_| format!("is below {rule}")),
            "maximum" => value
                .as_f64()
                .filter(|n| *n > bound())
                .map(|_| format!("is above {rule}")),
            "pattern" => {
                let pattern = Regex::new(rule.as_str().expect("a pattern")).expect("a regex");
                value
                    .as_str()
                    .filter(|s| !pattern.is_match(s))
                    .map(|_| format!("doesn't match {rule}"))
            }
            "format" if rule == "date-time" => value
                .as_str()
                .filter(|s| DateTime::parse_from_rfc3339(s).is_err())
                .map(|_| "isn't an RFC 3339 date-time".into()),
            _ => return Err(format!("{at}: unsupported keyword {keyword}: {rule}")),
        };
        if let Some(why) = violation {
            return Err(format!("{at}: {why}"));
        }
    }
    Ok(())
}

fn validate(manifest: &Value) -> Result<(), String> {
    let schema: Value = serde_json::from_str(SCHEMA).expect("the schema is JSON");
    check(&schema, &schema, manifest, "manifest")
}

/// Asserts that the schema refuses `manifest` for the reason `expected`
/// starts.
fn refuses(manifest: &Value, expected: &str) {
    match validate(manifest) {
        Ok(()) => panic!("accepted a manifest it should refuse with {expected:?}"),
        Err(why) => assert!(why.starts_with(expected), "{why:?} isn't {expected:?}"),
    }
}

/// A dev manifest that also lists a previous transport key version.
fn dev_manifest() -> Value {
    let dir = std::env::temp_dir().join(format!("relational-tee-schema-{}", uuid::Uuid::new_v4()));
    generate_missing(&dir).expect("dev keys");
    std::fs::copy(
        key_path(&dir, KeyName::StorageRoot),
        previous_key_path(&dir, KeyName::Transport),
    )
    .unwrap();
    let manifest = Manifest::for_dev_keys(
        &dir,
        "dev",
        dev_maa::DEFAULT_ISSUER,
        COMMIT,
        1_790_000_000,
        Utc::now(),
    );
    let _ = std::fs::remove_dir_all(&dir);
    manifest.unwrap().payload()
}

/// A complete manifest, as one for the pilot would be.
fn pilot_manifest() -> Value {
    let hex = |digit: &str| digit.repeat(64);
    json!({
        "environment": "pilot",
        "sequence": 42,
        "not_before": "2026-11-02T10:00:00Z",
        "not_after": "2026-12-02T10:00:00Z",
        "claim_sets": [{
            "authority": "https://sharedweu.weu.attest.azure.net",
            "x-ms-attestation-type": "sevsnpvm",
            "x-ms-compliance-status": "azure-compliant-uvm",
            "x-ms-sevsnpvm-is-debuggable": false,
            "x-ms-sevsnpvm-vmpl": 0,
            "x-ms-sevsnpvm-hostdata": [hex("a"), hex("b")],
        }],
        "keys": {
            "transport": [{
                "kid": "x0yNbvUkexdtgBGoYjiWyrbGVd8ajpV9gZSZQHCP9lY",
                "version": "0123456789abcdef0123456789abcdef",
            }],
            "tls": [{
                "version": "fedcba9876543210fedcba9876543210",
                "spki_sha256": "zKxxZcM+1VDaOJxnJzx10+uvq4HU3td+DzysmuW77U8=",
            }],
        },
        "images": {
            "worker": format!("sha256:{}", hex("c")),
            "skr": format!("sha256:{}", hex("d")),
        },
        "tools": { "confcom": "1.2.3", "dmverity_vhd": "v1.0.0" },
        "provenance": {
            "commit": COMMIT,
            "flake_lock_sha256": hex("e"),
            "nix_output":
                "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-docker-image-relational-tee.tar.gz",
            "layers": [hex("f")],
        },
    })
}

/// `manifest` without the member or item at `pointer`.
fn without(mut manifest: Value, pointer: &str) -> Value {
    let (parent, last) = pointer.rsplit_once('/').expect("a JSON pointer");
    match manifest.pointer_mut(parent).expect(pointer) {
        Value::Object(members) => {
            members.remove(last).expect(pointer);
        }
        Value::Array(items) => {
            items.remove(last.parse().expect(pointer));
        }
        _ => panic!("{pointer} has no parent"),
    }
    manifest
}

/// `manifest` with `value` at `pointer`.
fn with(mut manifest: Value, pointer: &str, value: Value) -> Value {
    *manifest.pointer_mut(pointer).expect(pointer) = value;
    manifest
}

#[test]
fn dev_and_pilot_manifests_match_the_schema() {
    let dev = dev_manifest();
    assert_eq!(dev["keys"]["transport"][1]["version"], "previous");
    validate(&dev).unwrap();
    validate(&pilot_manifest()).unwrap();
}

#[test]
fn the_schema_requires_what_workers_and_the_dashboard_read() {
    let dev = dev_manifest();
    for pointer in [
        "/environment",
        "/sequence",
        "/not_before",
        "/not_after",
        "/claim_sets",
        "/claim_sets/0/authority",
        "/claim_sets/0/x-ms-sevsnpvm-hostdata",
        "/keys/transport",
        "/keys/transport/0/kid",
        "/provenance/commit",
    ] {
        let (parent, member) = pointer.rsplit_once('/').unwrap();
        refuses(
            &without(dev.clone(), pointer),
            &format!("manifest{parent}: lacks {member}"),
        );
    }
}

#[test]
fn the_schema_refuses_what_clients_would_misread() {
    let dev = dev_manifest();
    // A claim set naming a claim clients don't check would promise a check
    // that never happens.
    let mut extra_claim = dev.clone();
    extra_claim["claim_sets"][0]["x-ms-sevsnpvm-guestsvn"] = json!(3);
    refuses(
        &extra_claim,
        "manifest/claim_sets/0: has an unknown member x-ms-sevsnpvm-guestsvn",
    );
    let mut extra_member = dev.clone();
    extra_member["signature"] = json!("detached");
    refuses(&extra_member, "manifest: has an unknown member signature");
    for (pointer, value, expected) in [
        (
            "/claim_sets/0/x-ms-sevsnpvm-is-debuggable",
            json!(true),
            "isn't false",
        ),
        (
            "/claim_sets/0/x-ms-sevsnpvm-hostdata/0",
            json!("DE".repeat(32)),
            "doesn't match",
        ),
        (
            "/keys/transport/0/kid",
            json!("x".repeat(42)),
            "doesn't match",
        ),
        ("/sequence", json!(1u64 << 53), "is above"),
        (
            "/not_after",
            json!("2026-10-30T12:00:21+02:00"),
            "doesn't match",
        ),
        (
            "/not_before",
            json!("2026-02-30T10:00:00Z"),
            "isn't an RFC 3339 date-time",
        ),
    ] {
        refuses(
            &with(dev.clone(), pointer, value),
            &format!("manifest{pointer}: {expected}"),
        );
    }
}

#[test]
fn outside_dev_a_manifest_names_what_rebuilds_its_release() {
    let pilot = pilot_manifest();
    refuses(&without(pilot.clone(), "/images"), "manifest: lacks images");
    refuses(&without(pilot.clone(), "/tools"), "manifest: lacks tools");
    refuses(
        &without(pilot.clone(), "/provenance/layers"),
        "manifest/provenance: lacks layers",
    );
    refuses(
        &with(pilot.clone(), "/provenance/commit", json!("dev")),
        "manifest/provenance/commit: doesn't match",
    );
    refuses(
        &with(
            pilot,
            "/claim_sets/0/authority",
            json!("http://localhost:9000"),
        ),
        "manifest/claim_sets/0/authority: doesn't match",
    );
    let staging = with(dev_manifest(), "/environment", json!("staging"));
    assert!(validate(&staging).is_err());
}

#[test]
fn the_checker_refuses_keywords_it_does_not_implement() {
    let schema = json!({ "type": "object", "oneOf": [] });
    let refused = check(&schema, &schema, &json!({}), "").unwrap_err();
    assert!(refused.contains("oneOf"), "{refused}");
}
