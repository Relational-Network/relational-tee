// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Checking an upload against its pool's schema, which the pool's analysis
//! definition sets: exactly the schema's headers, in any order, and every
//! date as DD/MM/YYYY.

use std::collections::{HashMap, HashSet};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use utoipa::ToSchema;

use crate::analysis::dates;

/// Maximum number of validation errors returned per request.
pub const MAX_VALIDATION_ERRORS: usize = 100;

/// A column's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    Text,
    /// DD/MM/YYYY.
    Date,
}

impl<'de> Deserialize<'de> for FieldType {
    // Pools created before analysis definitions stored finer types
    // (`{"varchar": 100}`, `"integer"`, `"date_dd_mm_yyyy"`, ...): they read
    // as text, and their dates as dates.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        let name = match &value {
            serde_json::Value::String(name) => name.as_str(),
            serde_json::Value::Object(map) if map.len() == 1 => {
                map.keys().next().map(String::as_str).unwrap_or_default()
            }
            _ => return Err(D::Error::custom("expected a field type")),
        };
        match name {
            "text" | "char" | "varchar" | "integer" | "decimal" | "flag01" => Ok(Self::Text),
            "date" | "date_dd_mm_yyyy" => Ok(Self::Date),
            other => Err(D::Error::unknown_variant(other, &["text", "date"])),
        }
    }
}

/// One column of a pool's schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FieldSchema {
    /// The CSV header.
    pub name: String,
    pub field_type: FieldType,
    pub nullable: bool,
}

/// One validation error in a CSV file.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ValidationError {
    /// Data row number (1-indexed, excludes header row).
    pub row: usize,
    /// Column name.
    pub field: String,
    /// Human-readable validation error.
    pub message: String,
}

/// Validation output for CSV pre-checks and upload gating.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ValidationSummary {
    pub valid: bool,
    pub errors: Vec<ValidationError>,
    pub rows_validated: usize,
}

struct Errors(Vec<ValidationError>);

impl Errors {
    fn full(&self) -> bool {
        self.0.len() >= MAX_VALIDATION_ERRORS
    }

    fn push(&mut self, row: usize, field: &str, message: String) {
        if !self.full() {
            self.0.push(ValidationError {
                row,
                field: field.to_string(),
                message,
            });
        }
    }
}

/// Check `data` against `schema`: exactly its headers, in any order, then
/// every row's values. A header problem stops the check.
pub fn validate_csv_bytes(data: &[u8], schema: &[FieldSchema]) -> ValidationSummary {
    let mut errors = Errors(Vec::new());
    let mut rows_validated = 0usize;
    let summary = |errors: Errors, rows_validated| ValidationSummary {
        valid: errors.0.is_empty(),
        errors: errors.0,
        rows_validated,
    };

    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(data);
    let headers = match reader.headers() {
        Ok(h) => h.clone(),
        Err(_) => {
            errors.push(0, "header", "Could not parse CSV headers".to_string());
            return summary(errors, rows_validated);
        }
    };
    let mut index = HashMap::new();
    for (i, header) in headers.iter().enumerate() {
        if index.insert(header.trim(), i).is_some() {
            errors.push(0, header, format!("Duplicate column: {header}"));
        }
    }
    let names: HashSet<&str> = schema.iter().map(|f| f.name.as_str()).collect();
    for field in schema {
        if !index.contains_key(field.name.as_str()) {
            errors.push(
                0,
                &field.name,
                format!("Missing required column: {}", field.name),
            );
        }
    }
    for header in headers.iter() {
        if !names.contains(header.trim()) {
            errors.push(
                0,
                header,
                format!("Unexpected column not in schema: {header}"),
            );
        }
    }
    if !errors.0.is_empty() {
        return summary(errors, rows_validated);
    }

    for (row_idx, row_result) in reader.records().enumerate() {
        if errors.full() {
            break;
        }
        let Ok(record) = row_result else {
            errors.push(row_idx + 1, "row", "Malformed CSV row".to_string());
            continue;
        };
        rows_validated += 1;
        for field in schema {
            let value = record.get(index[field.name.as_str()]).unwrap_or("").trim();
            if let Some(message) = check_value(value, field) {
                errors.push(row_idx + 1, &field.name, message);
            }
        }
    }
    summary(errors, rows_validated)
}

fn check_value(value: &str, field: &FieldSchema) -> Option<String> {
    if value.is_empty() {
        return (!field.nullable).then(|| "field is required".to_string());
    }
    match field.field_type {
        FieldType::Text => None,
        FieldType::Date => dates::parse(value)
            .is_none()
            .then(|| format!("Date must be DD/MM/YYYY, got '{value}'")),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const AWARDS_HEADER: &str = "Staff Number,Membership Number,Title,First Name,\
        Surname,Date of Birth,Employer,Employer Group,Award,Award Grade,Exam Board Date";

    /// The Awards Report's schema, as pool creation derives it.
    pub(crate) fn awards_schema() -> Vec<FieldSchema> {
        crate::analysis::definition::tests::awards_report().schema()
    }

    fn check(rows: &[&str]) -> ValidationSummary {
        validate_csv_bytes(rows.join("\n").as_bytes(), &awards_schema())
    }

    const ROW: &str = "000123,0100045,Ms,Aoife,Brennan,14/03/1988,AIB,AIB,\
        Professional Certificate in Financial Services,Merit,01/01/2026";

    #[test]
    fn an_upload_with_the_schemas_headers_passes() {
        let result = check(&[AWARDS_HEADER, ROW, ",,,,,,,,,,"]);
        assert!(result.valid, "{:?}", result.errors);
        assert_eq!(result.rows_validated, 2);

        // Header order doesn't matter.
        let mut header: Vec<&str> = AWARDS_HEADER.split(',').collect();
        let mut row: Vec<&str> = ROW.split(',').collect();
        header.reverse();
        row.reverse();
        let result = check(&[&header.join(","), &row.join(",")]);
        assert!(result.valid, "{:?}", result.errors);
    }

    #[test]
    fn headers_must_be_exactly_the_schemas() {
        let missing = check(&["Staff Number,Membership Number", "000123,0100045"]);
        assert!(missing
            .errors
            .iter()
            .any(|e| e.message == "Missing required column: Exam Board Date"));

        let extra = check(&[&format!("{AWARDS_HEADER},Notes"), &format!("{ROW},hi")]);
        assert!(extra
            .errors
            .iter()
            .any(|e| e.field == "Notes" && e.message.starts_with("Unexpected column")));

        let twice = check(&[&format!("{AWARDS_HEADER},Award"), &format!("{ROW},x")]);
        assert!(twice
            .errors
            .iter()
            .any(|e| e.message == "Duplicate column: Award"));
        assert_eq!(twice.rows_validated, 0, "a header problem stops the check");
    }

    #[test]
    fn dates_must_be_dd_mm_yyyy() {
        for bad in ["2026-01-01", "1/1/2026", "31/02/2026", "01/01/26", "soon"] {
            let row = ROW.replace("01/01/2026", bad);
            let result = check(&[AWARDS_HEADER, &row]);
            assert!(
                result.errors.iter().any(|e| e.row == 1
                    && e.field == "Exam Board Date"
                    && e.message.contains("DD/MM/YYYY")),
                "{bad}: {:?}",
                result.errors
            );
        }
    }

    #[test]
    fn a_short_row_is_malformed_and_errors_are_capped() {
        let result = check(&[AWARDS_HEADER, "000123,0100045"]);
        assert!(result
            .errors
            .iter()
            .any(|e| e.message == "Malformed CSV row"));

        let bad = ROW
            .replace("14/03/1988", "1988")
            .replace("01/01/2026", "2026");
        let rows: Vec<&str> = std::iter::once(AWARDS_HEADER)
            .chain(std::iter::repeat_n(bad.as_str(), 80))
            .collect();
        let result = check(&rows);
        assert_eq!(result.errors.len(), MAX_VALIDATION_ERRORS);
    }

    #[test]
    fn a_required_field_must_have_a_value() {
        let schema = vec![FieldSchema {
            name: "Staff Number".into(),
            field_type: FieldType::Text,
            nullable: false,
        }];
        let result = validate_csv_bytes(b"Staff Number\n\n \n000123\n", &schema);
        assert!(result
            .errors
            .iter()
            .any(|e| e.message == "field is required"));
    }

    #[test]
    fn older_field_types_still_load() {
        let stored = r#"[
            {"name":"a","field_type":{"varchar":100},"nullable":true},
            {"name":"b","field_type":"integer","nullable":false},
            {"name":"c","field_type":"date_dd_mm_yyyy","nullable":true},
            {"name":"d","field_type":{"decimal":{"precision":10,"scale":2}},"nullable":true},
            {"name":"e","field_type":"date","nullable":true}
        ]"#;
        let schema: Vec<FieldSchema> = serde_json::from_str(stored).unwrap();
        let types: Vec<FieldType> = schema.iter().map(|f| f.field_type).collect();
        use FieldType::{Date, Text};
        assert_eq!(types, [Text, Text, Date, Text, Date]);
        assert!(serde_json::from_str::<FieldType>(r#""blob""#).is_err());
        assert_eq!(serde_json::to_string(&Date).unwrap(), r#""date""#);
    }
}
