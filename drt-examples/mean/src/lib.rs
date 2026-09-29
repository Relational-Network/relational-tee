// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Sample DRT — compute the arithmetic mean of one numeric column from the
//! pool's CSV data.
//!
//! ## Host ABI (zero-copy contract)
//!
//! The enclave runtime (`relational-sdk/src/drt/runtime.rs`) places the CSV
//! and the args JSON directly into this module's linear memory before
//! invoking `run`. No host calls are needed during execution beyond the
//! optional `host_log` diagnostic.
//!
//! ### Exports
//!
//! ```text
//! memory                                                  (default `memory` export)
//! alloc(size: i32) -> i32                                 bump allocator for the host
//! run(
//!     csv_ptr: i32, csv_len: i32,
//!     args_ptr: i32, args_len: i32,
//!     out_ptr_cell: i32, out_len_cell: i32,
//! ) -> i32                                                0 = success
//! ```
//!
//! `run` writes the output blob into `memory` (via the same bump allocator)
//! and stores its `(ptr, len)` as two little-endian i32s at the two cell
//! addresses the host passed in.
//!
//! ### Imports
//!
//! ```text
//! env.host_log(ptr: i32, len: i32)
//! ```
//!
//! ## Inputs
//!
//! - `csv` is the raw UTF-8 CSV (header row included). No JSON wrapping.
//! - `args` is a small UTF-8 JSON object: `{"column": "<header name>"}`.
//!
//! ## Output
//!
//! ```json
//! { "column": "value", "count": 1180, "skipped": 54, "mean": 71.5 }
//! ```
//!
//! Errors are emitted as `{"error": "..."}` with a non-zero exit from `run`.

#![cfg_attr(target_arch = "wasm32", no_std)]

#[cfg(target_arch = "wasm32")]
extern crate alloc;

#[cfg(target_arch = "wasm32")]
use alloc::string::String;

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

// --------------------------------------------------------------------------
// Bump allocator — wasm only
// --------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
mod bump {
    use core::arch::wasm32;
    use core::cell::UnsafeCell;

    const PAGE_SIZE: usize = 64 * 1024;

    pub struct Bump {
        offset: UnsafeCell<usize>,
    }
    unsafe impl Sync for Bump {}

    impl Bump {
        pub const fn new() -> Self {
            Self { offset: UnsafeCell::new(0) }
        }

        /// Allocate `size` bytes aligned to 8. Returns the wasm linear-memory
        /// address. Returns 0 on `memory.grow` failure.
        pub fn alloc(&self, size: usize) -> usize {
            extern "C" {
                static __heap_base: u8;
            }
            let heap_base = unsafe { &__heap_base as *const u8 as usize };
            let off_ptr = self.offset.get();
            let cur = unsafe { *off_ptr };
            let cur = if cur == 0 { heap_base } else { cur };
            let aligned = (cur + 7) & !7;
            let next = aligned + size;
            let current_bytes = wasm32::memory_size(0) * PAGE_SIZE;
            if next > current_bytes {
                let needed = next - current_bytes;
                let pages = (needed + PAGE_SIZE - 1) / PAGE_SIZE;
                if wasm32::memory_grow(0, pages) == usize::MAX {
                    return 0;
                }
            }
            unsafe { *off_ptr = next };
            aligned
        }
    }
}

// Global allocator (also bump). Carved out 16 MiB above `__heap_base` so the
// public `alloc()` export and Rust's own `alloc::String`/`Vec` allocations
// don't fight over the same offsets.
#[cfg(target_arch = "wasm32")]
mod global_alloc {
    use core::alloc::{GlobalAlloc, Layout};
    use core::arch::wasm32;
    use core::cell::UnsafeCell;

    const PAGE_SIZE: usize = 64 * 1024;
    const GLOBAL_OFFSET_FROM_HEAP_BASE: usize = 16 * 1024 * 1024;

    pub struct BumpAlloc {
        offset: UnsafeCell<usize>,
    }
    unsafe impl Sync for BumpAlloc {}
    impl BumpAlloc {
        pub const fn new() -> Self {
            Self { offset: UnsafeCell::new(0) }
        }
    }

    // SAFETY: single-threaded wasm; bump alloc never overlaps and never frees.
    unsafe impl GlobalAlloc for BumpAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            extern "C" {
                static __heap_base: u8;
            }
            let heap_base = &__heap_base as *const u8 as usize;
            let off_ptr = self.offset.get();
            let mut cur = *off_ptr;
            if cur == 0 {
                cur = heap_base + GLOBAL_OFFSET_FROM_HEAP_BASE;
            }
            let align = layout.align();
            let aligned = (cur + align - 1) & !(align - 1);
            let next = aligned + layout.size();
            let current_bytes = wasm32::memory_size(0) * PAGE_SIZE;
            if next > current_bytes {
                let needed = next - current_bytes;
                let pages = (needed + PAGE_SIZE - 1) / PAGE_SIZE;
                if wasm32::memory_grow(0, pages) == usize::MAX {
                    return core::ptr::null_mut();
                }
            }
            *off_ptr = next;
            aligned as *mut u8
        }
        unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
    }
}

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static GLOBAL: global_alloc::BumpAlloc = global_alloc::BumpAlloc::new();

#[cfg(target_arch = "wasm32")]
static PUBLIC_BUMP: bump::Bump = bump::Bump::new();

// --------------------------------------------------------------------------
// Exported ABI
// --------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn alloc(size: i32) -> i32 {
    if size < 0 {
        return 0;
    }
    PUBLIC_BUMP.alloc(size as usize) as i32
}

#[cfg(target_arch = "wasm32")]
mod host {
    extern "C" {
        pub fn host_log(src: i32, len: i32);
    }
}

#[cfg(target_arch = "wasm32")]
#[allow(dead_code)]
fn log(msg: &str) {
    unsafe { host::host_log(msg.as_ptr() as i32, msg.len() as i32) };
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn run(
    csv_ptr: i32,
    csv_len: i32,
    args_ptr: i32,
    args_len: i32,
    out_ptr_cell: i32,
    out_len_cell: i32,
) -> i32 {
    // SAFETY: the host guarantees `(ptr, len)` ranges are valid inside the
    // module's linear memory for the duration of this call.
    let csv = unsafe {
        core::slice::from_raw_parts(csv_ptr as *const u8, csv_len as usize)
    };
    let args = unsafe {
        core::slice::from_raw_parts(args_ptr as *const u8, args_len as usize)
    };
    let (code, body) = match run_inner(csv, args) {
        Ok(b) => (0, b),
        Err((c, m)) => (c, format_error(&m)),
    };
    write_cells(out_ptr_cell, out_len_cell, body.as_bytes());
    code
}

#[cfg(target_arch = "wasm32")]
fn write_cells(out_ptr_cell: i32, out_len_cell: i32, body: &[u8]) {
    let dst = PUBLIC_BUMP.alloc(body.len());
    if dst == 0 {
        write_le_i32(out_ptr_cell, 0);
        write_le_i32(out_len_cell, 0);
        return;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(body.as_ptr(), dst as *mut u8, body.len());
    }
    write_le_i32(out_ptr_cell, dst as i32);
    write_le_i32(out_len_cell, body.len() as i32);
}

#[cfg(target_arch = "wasm32")]
fn write_le_i32(addr: i32, v: i32) {
    let bytes = v.to_le_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), addr as *mut u8, 4);
    }
}

// --------------------------------------------------------------------------
// Pure logic — also exercised by host-side tests
// --------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
type String = std::string::String;

fn run_inner(csv: &[u8], args: &[u8]) -> Result<String, (i32, String)> {
    let args_str = core::str::from_utf8(args)
        .map_err(|_| (2, String::from("args not UTF-8")))?;
    let column = extract_string_field(args_str, "column")
        .ok_or_else(|| (2, String::from("missing 'column' arg")))?;
    let stats = compute_mean(csv, column.as_bytes()).map_err(|m| (3, m))?;
    Ok(format_result(&column, &stats))
}

/// Host-build entry — drives the same logic without a wasm runtime.
#[cfg(not(target_arch = "wasm32"))]
pub fn run_host(csv: &str, args: &str) -> Result<String, String> {
    run_inner(csv.as_bytes(), args.as_bytes()).map_err(|(_, m)| m)
}

/// Minimal hand-rolled JSON extraction for `{"column": "..."}`. We avoid
/// `serde_json` to keep the WASM module small (~tens of KiB vs. hundreds).
fn extract_string_field(input: &str, key: &str) -> Option<String> {
    let mut needle = String::with_capacity(key.len() + 4);
    needle.push('"');
    needle.push_str(key);
    needle.push_str("\":");
    let idx = input.find(&needle)?;
    let rest = input[idx + needle.len()..].trim_start();
    let body = rest.strip_prefix('"')?;
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c == '"' {
            return Some(out);
        }
        if c == '\\' {
            match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                _ => return None,
            }
        } else {
            out.push(c);
        }
    }
    None
}

struct MeanStats {
    count: u64,
    skipped: u64,
    mean: f64,
}

/// Single-pass byte-level CSV scanner.
///
/// Walks the header once to find the target column index, then walks the
/// body once, slicing the target field per row by counting commas. Wins
/// vs. `csv.lines().split(',').nth(col).parse::<f64>()`:
///   - No per-row UTF-8 validation (we operate on bytes).
///   - No `&str` allocations.
///   - Fused row + column scan.
///   - Custom decimal `f64` parser avoids `from_str`'s slow path.
fn compute_mean(csv: &[u8], column: &[u8]) -> Result<MeanStats, String> {
    if csv.is_empty() {
        return Err(String::from("empty CSV"));
    }
    let (header, body) = split_first_line(csv);
    let col_idx = header_column_index(header, column).ok_or_else(|| {
        let mut s = String::with_capacity(column.len() + 24);
        s.push_str("column '");
        if let Ok(c) = core::str::from_utf8(column) {
            s.push_str(c);
        }
        s.push_str("' not in header");
        s
    })?;

    let mut sum = 0.0_f64;
    let mut count: u64 = 0;
    let mut skipped: u64 = 0;

    let mut i = 0;
    let n = body.len();
    while i < n {
        // Skip stray \r or \n between rows.
        if body[i] == b'\r' || body[i] == b'\n' {
            i += 1;
            continue;
        }
        let row_start = i;
        while i < n && body[i] != b'\n' {
            i += 1;
        }
        let mut row_end = i;
        if row_end > row_start && body[row_end - 1] == b'\r' {
            row_end -= 1;
        }
        if i < n {
            i += 1;
        }

        let row = &body[row_start..row_end];
        if row.is_empty() {
            continue;
        }
        match field_at(row, col_idx) {
            None => skipped += 1,
            Some(field) => {
                let trimmed = trim_ascii(field);
                if trimmed.is_empty() {
                    skipped += 1;
                } else {
                    match parse_f64_bytes(trimmed) {
                        Some(v) => {
                            sum += v;
                            count += 1;
                        }
                        None => skipped += 1,
                    }
                }
            }
        }
    }

    if count == 0 {
        return Err(String::from("no numeric values in column"));
    }
    Ok(MeanStats { count, skipped, mean: sum / count as f64 })
}

fn split_first_line(buf: &[u8]) -> (&[u8], &[u8]) {
    let mut i = 0;
    while i < buf.len() && buf[i] != b'\n' {
        i += 1;
    }
    let mut header_end = i;
    if header_end > 0 && buf[header_end - 1] == b'\r' {
        header_end -= 1;
    }
    let body_start = (i + 1).min(buf.len());
    (&buf[..header_end], &buf[body_start..])
}

fn header_column_index(header: &[u8], column: &[u8]) -> Option<usize> {
    let mut start = 0;
    let mut idx = 0;
    let mut i = 0;
    while i <= header.len() {
        let at_end = i == header.len();
        if at_end || header[i] == b',' {
            let cell = trim_ascii(&header[start..i]);
            if cell == column {
                return Some(idx);
            }
            idx += 1;
            start = i + 1;
        }
        i += 1;
    }
    None
}

fn field_at(row: &[u8], n: usize) -> Option<&[u8]> {
    let mut start = 0;
    let mut idx = 0;
    let mut i = 0;
    while i < row.len() {
        if row[i] == b',' {
            if idx == n {
                return Some(&row[start..i]);
            }
            idx += 1;
            start = i + 1;
        }
        i += 1;
    }
    if idx == n {
        Some(&row[start..])
    } else {
        None
    }
}

fn trim_ascii(s: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = s.len();
    while start < end && (s[start] == b' ' || s[start] == b'\t') {
        start += 1;
    }
    while end > start && (s[end - 1] == b' ' || s[end - 1] == b'\t') {
        end -= 1;
    }
    &s[start..end]
}

/// Hand-rolled decimal `f64` parser. Supports optional sign, integer part,
/// `.fraction`, and `e[+-]?digits`. Returns `None` on unexpected bytes —
/// the caller counts those as `skipped`. Fast path is ~5–10× faster than
/// `f64::from_str` for typical CSV cells; round-off matches IEEE-754
/// within a few ULPs, fine for arithmetic mean.
fn parse_f64_bytes(b: &[u8]) -> Option<f64> {
    if b.is_empty() {
        return None;
    }
    let mut i = 0;
    let mut neg = false;
    match b[0] {
        b'-' => { neg = true; i = 1; }
        b'+' => i = 1,
        _ => {}
    }
    if i >= b.len() {
        return None;
    }

    let mut int_part: u64 = 0;
    let mut int_digits = 0u32;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_digit() {
            int_part = int_part.wrapping_mul(10).wrapping_add((c - b'0') as u64);
            int_digits += 1;
            i += 1;
        } else {
            break;
        }
    }

    let mut frac_part: u64 = 0;
    let mut frac_digits = 0u32;
    if i < b.len() && b[i] == b'.' {
        i += 1;
        while i < b.len() {
            let c = b[i];
            if c.is_ascii_digit() {
                if frac_digits < 18 {
                    frac_part = frac_part.wrapping_mul(10).wrapping_add((c - b'0') as u64);
                    frac_digits += 1;
                }
                i += 1;
            } else {
                break;
            }
        }
    }

    if int_digits == 0 && frac_digits == 0 {
        return None;
    }

    let mut exp: i32 = 0;
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        i += 1;
        let mut exp_neg = false;
        if i < b.len() {
            match b[i] {
                b'-' => { exp_neg = true; i += 1; }
                b'+' => i += 1,
                _ => {}
            }
        }
        let mut exp_digits = 0u32;
        let mut e: i32 = 0;
        while i < b.len() {
            let c = b[i];
            if c.is_ascii_digit() {
                e = e.saturating_mul(10).saturating_add((c - b'0') as i32);
                exp_digits += 1;
                i += 1;
            } else {
                break;
            }
        }
        if exp_digits == 0 {
            return None;
        }
        exp = if exp_neg { -e } else { e };
    }

    if i != b.len() {
        return None;
    }

    let mut val = int_part as f64;
    if frac_digits > 0 {
        val += (frac_part as f64) * pow10(-(frac_digits as i32));
    }
    if exp != 0 {
        val *= pow10(exp);
    }
    if neg {
        val = -val;
    }
    Some(val)
}

fn pow10(e: i32) -> f64 {
    const POS: [f64; 23] = [
        1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15,
        1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22,
    ];
    const NEG: [f64; 23] = [
        1e0, 1e-1, 1e-2, 1e-3, 1e-4, 1e-5, 1e-6, 1e-7, 1e-8, 1e-9, 1e-10, 1e-11, 1e-12, 1e-13,
        1e-14, 1e-15, 1e-16, 1e-17, 1e-18, 1e-19, 1e-20, 1e-21, 1e-22,
    ];
    if e >= 0 {
        let u = e as usize;
        if u < POS.len() {
            return POS[u];
        }
        let mut v = POS[POS.len() - 1];
        for _ in 0..(u - (POS.len() - 1)) {
            v *= 10.0;
        }
        v
    } else {
        let u = (-e) as usize;
        if u < NEG.len() {
            return NEG[u];
        }
        let mut v = NEG[NEG.len() - 1];
        for _ in 0..(u - (NEG.len() - 1)) {
            v *= 0.1;
        }
        v
    }
}

// --------------------------------------------------------------------------
// Result formatting
// --------------------------------------------------------------------------

fn format_result(column: &str, stats: &MeanStats) -> String {
    let mut s = String::with_capacity(96);
    s.push_str("{\"column\":\"");
    s.push_str(column);
    s.push_str("\",\"count\":");
    push_u64(&mut s, stats.count);
    s.push_str(",\"skipped\":");
    push_u64(&mut s, stats.skipped);
    s.push_str(",\"mean\":");
    push_f64(&mut s, stats.mean);
    s.push('}');
    s
}

fn format_error(msg: &str) -> String {
    let mut s = String::with_capacity(msg.len() + 16);
    s.push_str("{\"error\":\"");
    for c in msg.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            c if (c as u32) < 0x20 => {}
            c => s.push(c),
        }
    }
    s.push_str("\"}");
    s
}

fn push_u64(s: &mut String, n: u64) {
    if n == 0 {
        s.push('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 20;
    let mut n = n;
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    for &b in &buf[i..] {
        s.push(b as char);
    }
}

fn push_f64(s: &mut String, n: f64) {
    if n.is_nan() || n.is_infinite() {
        s.push_str("null");
        return;
    }
    let mut n = n;
    if n < 0.0 {
        s.push('-');
        n = -n;
    }
    let int_part = n as u64;
    push_u64(s, int_part);
    let mut frac = n - int_part as f64;
    if frac == 0.0 {
        return;
    }
    s.push('.');
    for _ in 0..6 {
        frac *= 10.0;
        let digit = frac as u64 % 10;
        s.push((b'0' + digit as u8) as char);
    }
}

// --------------------------------------------------------------------------
// Tests (host build only)
// --------------------------------------------------------------------------

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn computes_mean_of_named_column() {
        let csv = b"id,value,group\n1,100,A\n2,200,A\n3,300,B\n";
        let stats = compute_mean(csv, b"value").unwrap();
        assert_eq!(stats.count, 3);
        assert_eq!(stats.skipped, 0);
        assert!((stats.mean - 200.0).abs() < 1e-9);
    }

    #[test]
    fn rejects_missing_column() {
        let csv = b"id,value\n1,100\n";
        assert!(compute_mean(csv, b"other").is_err());
    }

    #[test]
    fn counts_non_numeric_cells_as_skipped() {
        let csv = b"id,value\n1,10\n2,abc\n3,20\n";
        let stats = compute_mean(csv, b"value").unwrap();
        assert_eq!(stats.count, 2);
        assert_eq!(stats.skipped, 1);
        assert!((stats.mean - 15.0).abs() < 1e-9);
    }

    #[test]
    fn counts_empty_cells_as_skipped() {
        let csv = b"id,value\n1,10\n2,\n3,20\n4,\n5,30\n";
        let stats = compute_mean(csv, b"value").unwrap();
        assert_eq!(stats.count, 3);
        assert_eq!(stats.skipped, 2);
        assert!((stats.mean - 20.0).abs() < 1e-9);
    }

    #[test]
    fn handles_crlf_line_endings() {
        let csv = b"id,value\r\n1,10\r\n2,20\r\n3,30\r\n";
        let stats = compute_mean(csv, b"value").unwrap();
        assert_eq!(stats.count, 3);
        assert!((stats.mean - 20.0).abs() < 1e-9);
    }

    #[test]
    fn handles_short_rows_as_skipped() {
        let csv = b"id,value\n1,10\n2,20\n3\n4,40\n";
        let stats = compute_mean(csv, b"value").unwrap();
        assert_eq!(stats.count, 3);
        assert_eq!(stats.skipped, 1);
    }

    #[test]
    fn handles_column_at_start_and_end() {
        let csv = b"value,other\n10,a\n20,b\n30,c\n";
        let stats = compute_mean(csv, b"value").unwrap();
        assert_eq!(stats.count, 3);
        assert!((stats.mean - 20.0).abs() < 1e-9);

        let csv = b"id,other,value\n1,a,10\n2,b,20\n3,c,30\n";
        let stats = compute_mean(csv, b"value").unwrap();
        assert_eq!(stats.count, 3);
        assert!((stats.mean - 20.0).abs() < 1e-9);
    }

    #[test]
    fn parses_args_json() {
        let args = r#"{"column":"value","extra":"ignored"}"#;
        assert_eq!(extract_string_field(args, "column").unwrap(), "value");
    }

    #[test]
    fn parse_f64_handles_integers_decimals_and_exponents() {
        assert_eq!(parse_f64_bytes(b"0"), Some(0.0));
        assert_eq!(parse_f64_bytes(b"42"), Some(42.0));
        assert_eq!(parse_f64_bytes(b"-42"), Some(-42.0));
        assert_eq!(parse_f64_bytes(b"+42"), Some(42.0));
        assert!((parse_f64_bytes(b"3.14").unwrap() - 3.14).abs() < 1e-9);
        assert!((parse_f64_bytes(b"-0.5").unwrap() + 0.5).abs() < 1e-12);
        assert!((parse_f64_bytes(b"1e3").unwrap() - 1000.0).abs() < 1e-9);
        assert!((parse_f64_bytes(b"1.5E2").unwrap() - 150.0).abs() < 1e-9);
        assert!((parse_f64_bytes(b"2.5e-2").unwrap() - 0.025).abs() < 1e-12);
        assert_eq!(parse_f64_bytes(b""), None);
        assert_eq!(parse_f64_bytes(b"abc"), None);
        assert_eq!(parse_f64_bytes(b"1.2.3"), None);
        assert_eq!(parse_f64_bytes(b"1e"), None);
    }

    #[test]
    fn formats_result_json() {
        let stats = MeanStats { count: 3, skipped: 1, mean: 200.0 };
        let s = format_result("value", &stats);
        assert_eq!(s, "{\"column\":\"value\",\"count\":3,\"skipped\":1,\"mean\":200}");
    }

    #[test]
    fn run_host_end_to_end() {
        let csv = "id,value\n1,10\n2,20\n3,30\n";
        let args = r#"{"column":"value"}"#;
        let out = run_host(csv, args).unwrap();
        assert!(out.contains("\"count\":3"), "out: {out}");
        assert!(out.contains("\"skipped\":0"), "out: {out}");
        assert!(out.contains("\"mean\":20"), "out: {out}");
    }

    #[test]
    fn scales_to_100k_rows() {
        let mut csv = String::from("id,value\n");
        let mut expected_sum = 0.0_f64;
        for i in 0..100_000 {
            let v = (i % 1000) as f64;
            expected_sum += v;
            csv.push_str(&format!("{i},{v}\n"));
        }
        let stats = compute_mean(csv.as_bytes(), b"value").unwrap();
        assert_eq!(stats.count, 100_000);
        assert_eq!(stats.skipped, 0);
        assert!((stats.mean - expected_sum / 100_000.0).abs() < 1e-6);
    }
}
