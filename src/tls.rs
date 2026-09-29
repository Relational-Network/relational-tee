// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Reading the served certificate: just enough DER to find the leaf's
//! expiry, for readiness and `/health`.

use chrono::{DateTime, NaiveDateTime, Utc};

/// One DER element: its tag, its contents, and what follows it.
fn element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        l if l < 0x80 => (l as usize, rest),
        0x81..=0x84 => {
            let n = (first & 0x7f) as usize;
            if rest.len() < n {
                return None;
            }
            let len = rest[..n]
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | *b as usize);
            (len, &rest[n..])
        }
        _ => return None,
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

const SEQUENCE: u8 = 0x30;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
const VERSION: u8 = 0xa0;

/// The `notAfter` of a DER certificate.
pub fn not_after(der: &[u8]) -> Option<DateTime<Utc>> {
    let (tag, certificate, _) = element(der)?;
    (tag == SEQUENCE).then_some(())?;
    let (tag, tbs, _) = element(certificate)?;
    (tag == SEQUENCE).then_some(())?;
    let mut fields = tbs;
    if fields.first() == Some(&VERSION) {
        fields = element(fields)?.2;
    }
    // serialNumber, signature, issuer, then validity.
    for _ in 0..3 {
        fields = element(fields)?.2;
    }
    let (tag, validity, _) = element(fields)?;
    (tag == SEQUENCE).then_some(())?;
    let (_, _, rest) = element(validity)?;
    let (tag, time, _) = element(rest)?;
    let text = std::str::from_utf8(time).ok()?;
    let parsed = match tag {
        UTC_TIME => {
            // Two-digit years: 50–99 are 19xx, 00–49 are 20xx (RFC 5280).
            let year: u32 = text.get(..2)?.parse().ok()?;
            let century = if year >= 50 { "19" } else { "20" };
            NaiveDateTime::parse_from_str(&format!("{century}{text}"), "%Y%m%d%H%M%SZ").ok()?
        }
        GENERALIZED_TIME => NaiveDateTime::parse_from_str(text, "%Y%m%d%H%M%SZ").ok()?,
        _ => return None,
    };
    Some(parsed.and_utc())
}

/// The `notAfter` of the first certificate in a PEM chain.
pub fn leaf_not_after(pem: &[u8]) -> Option<DateTime<Utc>> {
    let leaf = rustls_pemfile::certs(&mut &pem[..]).next()?.ok()?;
    not_after(leaf.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if contents.len() < 0x80 {
            out.push(contents.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(contents);
        out
    }

    /// A certificate skeleton with the given validity times.
    fn certificate(not_before: (u8, &str), not_after: (u8, &str), padding: usize) -> Vec<u8> {
        let tbs = [
            der(VERSION, &der(0x02, &[2])),
            der(0x02, &[1]),
            der(SEQUENCE, &[]),
            der(SEQUENCE, &vec![0x05; padding]),
            der(
                SEQUENCE,
                &[
                    der(not_before.0, not_before.1.as_bytes()),
                    der(not_after.0, not_after.1.as_bytes()),
                ]
                .concat(),
            ),
        ]
        .concat();
        der(SEQUENCE, &der(SEQUENCE, &tbs))
    }

    #[test]
    fn reads_utc_and_generalized_times() {
        let utc = certificate((UTC_TIME, "250101000000Z"), (UTC_TIME, "351231235959Z"), 0);
        assert_eq!(
            not_after(&utc).unwrap().to_rfc3339(),
            "2035-12-31T23:59:59+00:00"
        );
        let generalized = certificate(
            (UTC_TIME, "250101000000Z"),
            (GENERALIZED_TIME, "20600101000000Z"),
            300,
        );
        assert_eq!(
            not_after(&generalized).unwrap().to_rfc3339(),
            "2060-01-01T00:00:00+00:00"
        );
        assert!(not_after(&utc[..utc.len() - 4]).is_none());
        assert!(not_after(b"not der").is_none());
    }
}
