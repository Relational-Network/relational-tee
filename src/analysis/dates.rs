// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Dates are DD/MM/YYYY in CSVs and the API, and `YYYY-MM-DD` inside SQLite,
//! where text order is date order.

use chrono::NaiveDate;

/// A DD/MM/YYYY date, exactly: two-digit day and month, four-digit year.
pub fn parse(value: &str) -> Option<NaiveDate> {
    let bytes = value.as_bytes();
    let shaped = bytes.len() == 10
        && bytes[2] == b'/'
        && bytes[5] == b'/'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 2 || i == 5 || b.is_ascii_digit());
    if !shaped {
        return None;
    }
    NaiveDate::parse_from_str(value, "%d/%m/%Y").ok()
}

/// A DD/MM/YYYY date as SQLite holds it.
pub fn to_sql(value: &str) -> Option<String> {
    parse(value).map(|d| d.format("%Y-%m-%d").to_string())
}

/// A date SQLite holds, as DD/MM/YYYY.
pub fn from_sql(value: &str) -> Option<String> {
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .ok()
        .map(|d| d.format("%d/%m/%Y").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_dd_mm_yyyy_parses() {
        assert_eq!(to_sql("01/02/2026").as_deref(), Some("2026-02-01"));
        assert_eq!(to_sql("29/02/2024").as_deref(), Some("2024-02-29"));
        for bad in [
            "2026-02-01",
            "1/2/2026",
            "01/02/26",
            "31/02/2026",
            "29/02/2025",
            "01-02-2026",
            "01/02/2026 10:00",
            " 01/02/2026",
            "",
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn sql_dates_come_back_as_dd_mm_yyyy() {
        assert_eq!(from_sql("2026-09-30").as_deref(), Some("30/09/2026"));
        assert_eq!(from_sql("30/09/2026"), None);
    }
}
