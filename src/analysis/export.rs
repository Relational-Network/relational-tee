// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Exports: every row a query matches, in its sort and without paging, as a
//! CSV or XLSX file of the definition's output columns, built in memory.
//!
//! Both formats are written a row at a time into a [`Bounded`] buffer, which
//! refuses to grow past the size limit and stops once the work's [`Stop`]
//! fires, so neither a large result nor a deadline can make an export
//! return part of a file, and an export holds little more than its file. An
//! XLSX file is a zip of XML parts; its worksheet is compressed into the
//! buffer as its rows are written, never held whole. Rows are counted before
//! any is written, so a result over the row limit is refused at once.
//! Nothing is truncated: an export over a limit fails.
//!
//! Cells are written as the API returns them: text exactly as stored, dates
//! as DD/MM/YYYY, an empty cell as nothing. A CSV cell that a spreadsheet
//! would read as a formula is prefixed with `'` ([`neutralise`]); an XLSX
//! cell is always a literal string, never a number, formula or link.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::io::{self, Cursor, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::error;
use utoipa::ToSchema;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipWriter};

use super::definition::Definition;
use super::query::{Query, QueryError};
use super::table::Table;
use crate::error::ApiError;
use crate::work::Stop;

/// The most rows an export holds.
pub const MAX_ROWS: u64 = 100_000;
/// The largest file an export makes.
pub const MAX_BYTES: usize = 50 << 20;
/// The longest text an XLSX cell holds, in UTF-16 units, as Excel counts.
const MAX_CELL_CHARS: usize = 32_767;
/// The most rows an XLSX worksheet holds, its header included.
const MAX_SHEET_ROWS: u32 = 1_048_576;
/// How many XLSX rows are written between checks of the work's stop, beyond
/// those its buffer makes as the compressed bytes arrive.
const STOP_EVERY: u32 = 1024;

/// A file format an export can take.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Csv,
    Xlsx,
}

impl Format {
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Csv => "text/csv; charset=utf-8",
            Self::Xlsx => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Xlsx => "xlsx",
        }
    }
}

/// How large an export may be, and how long it may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_rows: u64,
    pub max_bytes: usize,
    /// How long counting the rows may take, and then writing them.
    pub deadline: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_rows: MAX_ROWS,
            max_bytes: MAX_BYTES,
            deadline: super::runner::DEADLINE,
        }
    }
}

/// Why an export made no file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportError {
    /// The query doesn't fit the definition.
    Invalid(String),
    /// More rows match than an export holds.
    TooManyRows {
        matched: u64,
        max: u64,
    },
    /// The file would be larger than an export may be, or holds a cell
    /// larger than its format allows.
    TooLarge(String),
    /// The work's stop fired: its deadline passed, or nobody waits for it.
    Stopped,
    Failed(String),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) | Self::TooLarge(message) | Self::Failed(message) => {
                f.write_str(message)
            }
            Self::TooManyRows { matched, max } => write!(
                f,
                "{matched} rows match, and an export holds at most {max}; narrow the filters"
            ),
            Self::Stopped => f.write_str("the export stopped before it finished"),
        }
    }
}

impl From<QueryError> for ExportError {
    fn from(e: QueryError) -> Self {
        match e {
            QueryError::Invalid(message) => Self::Invalid(message),
            QueryError::Timeout => Self::Stopped,
            QueryError::Failed(message) => Self::Failed(message),
        }
    }
}

/// An export's error, as the API reports it. A stop is a timeout here: a
/// request whose client went away gets no response to read it in.
impl From<ExportError> for ApiError {
    fn from(e: ExportError) -> Self {
        match e {
            ExportError::Invalid(message) => {
                ApiError::bad_request(message).with_code("invalid_query")
            }
            e @ ExportError::TooManyRows { .. } => {
                ApiError::unprocessable(e.to_string()).with_code("export_too_many_rows")
            }
            ExportError::TooLarge(message) => {
                ApiError::unprocessable(message).with_code("export_too_large")
            }
            ExportError::Stopped => ApiError::unprocessable(
                "the export ran out of time; narrow the filters and try again",
            )
            .with_code("analysis_timeout"),
            ExportError::Failed(message) => {
                error!(error = %message, "An export failed");
                ApiError::internal("the export failed")
            }
        }
    }
}

/// Why a [`Bounded`] buffer refused a write, kept where the writer that
/// owns the buffer can read it after the write fails.
#[derive(Clone, Default)]
pub struct Refusal(Arc<AtomicU8>);

impl Refusal {
    const TOO_LARGE: u8 = 1;
    const STOPPED: u8 = 2;

    fn set(&self, why: u8) {
        self.0.store(why, Ordering::Relaxed);
    }

    /// The error a writer's failure stands for: the refusal, if the buffer
    /// refused a write, otherwise `failed`.
    fn error(&self, max: usize, failed: impl std::fmt::Display) -> ExportError {
        match self.0.load(Ordering::Relaxed) {
            Self::TOO_LARGE => ExportError::TooLarge(format!(
                "the file would be larger than an export may be ({} MiB); narrow the filters",
                max >> 20
            )),
            Self::STOPPED => ExportError::Stopped,
            _ => ExportError::Failed(format!("writing the export failed: {failed}")),
        }
    }
}

/// A file's bytes, in memory, refusing any write that would take them past
/// `max` bytes or that comes once `stop` has fired. A writer that sees the
/// refusal fails, so a file is either whole or not returned at all.
pub struct Bounded {
    out: Cursor<Vec<u8>>,
    max: usize,
    stop: Stop,
    refusal: Refusal,
}

impl Bounded {
    fn new(max: usize, stop: Stop) -> Self {
        Self {
            out: Cursor::new(Vec::new()),
            max,
            stop,
            refusal: Refusal::default(),
        }
    }
}

impl Write for Bounded {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let end = usize::try_from(self.out.position())
            .unwrap_or(usize::MAX)
            .saturating_add(data.len())
            .max(self.out.get_ref().len());
        if self.stop.stopped() {
            self.refusal.set(Refusal::STOPPED);
        } else if end > self.max {
            self.refusal.set(Refusal::TOO_LARGE);
        } else {
            return self.out.write(data);
        }
        Err(io::Error::other("the export's buffer refused the write"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The zip writer goes back to fill in each part's sizes, so readers find
/// them in its headers.
impl Seek for Bounded {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.out.seek(to)
    }
}

/// `value`, safe to open in a spreadsheet: one that starts as a formula
/// would (`=`, `+`, `-`, `@`, a tab or a carriage return) gets a leading
/// `'`, unless it is a plain amount, such as `-25.00` or `-€1,234.50`,
/// which a spreadsheet reads as a number rather than a formula.
pub fn neutralise(value: &str) -> Cow<'_, str> {
    match value.chars().next() {
        Some('=' | '+' | '-' | '@' | '\t' | '\r') if !is_amount(value) => {
            Cow::Owned(format!("'{value}"))
        }
        _ => Cow::Borrowed(value),
    }
}

/// Whether `value` is a plain amount: at most one sign and one currency
/// symbol (€, £ or $), in either order, then digits, grouped in threes by
/// commas after a first group of one to three if commas appear, and an
/// optional decimal part.
fn is_amount(value: &str) -> bool {
    let (mut sign, mut symbol) = (false, false);
    let mut rest = value;
    loop {
        let mut chars = rest.chars();
        match chars.next() {
            Some('+' | '-') if !sign => sign = true,
            Some('€' | '£' | '$') if !symbol => symbol = true,
            _ => break,
        }
        rest = chars.as_str();
    }
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let whole = match rest.split_once('.') {
        Some((whole, fraction)) if digits(fraction) => whole,
        Some(_) => return false,
        None => rest,
    };
    let mut groups = whole.split(',');
    let first = groups.next().unwrap_or_default();
    let mut rest = groups.peekable();
    if rest.peek().is_none() {
        return digits(first);
    }
    digits(first) && first.len() <= 3 && rest.all(|group| group.len() == 3 && digits(group))
}

/// A worksheet's name from `name`: Excel's forbidden characters left out,
/// at most 31 characters, and `Export` when nothing usable is left.
fn sheet_name(name: &str) -> String {
    let kept: String = name
        .chars()
        .filter(|c| !matches!(c, '[' | ']' | ':' | '*' | '?' | '/' | '\\') && !c.is_control())
        .take(31)
        .collect();
    let kept = kept.trim().trim_matches('\'').trim();
    if kept.is_empty() || kept.eq_ignore_ascii_case("history") {
        "Export".into()
    } else {
        kept.into()
    }
}

/// The letters of the 0-based column `index`: A to Z, then AA and on.
fn column_letters(index: usize) -> String {
    let mut n = index + 1;
    let mut letters = Vec::new();
    while n > 0 {
        letters.push(char::from(b'A' + ((n - 1) % 26) as u8));
        n = (n - 1) / 26;
    }
    letters.iter().rev().collect()
}

/// Whether `rest` starts with `_xHHHH_`, which Excel would read as an
/// escaped character rather than as the text itself.
fn reads_as_escape(rest: &[u8]) -> bool {
    rest.len() >= 7
        && rest[0] == b'_'
        && rest[1] == b'x'
        && rest[2..6].iter().all(u8::is_ascii_hexdigit)
        && rest[6] == b'_'
}

/// Append `value` to `xml` as element text that Excel reads back exactly:
/// XML's own escapes; the characters XML can't hold (control characters
/// other than tab and line feed, U+FFFE and U+FFFF) as Excel writes them,
/// `_xHHHH_`; and text that would read as such an escape with its `_`
/// escaped.
fn push_text(xml: &mut String, value: &str) {
    let bytes = value.as_bytes();
    for (i, c) in value.char_indices() {
        match c {
            '&' => xml.push_str("&amp;"),
            '<' => xml.push_str("&lt;"),
            '>' => xml.push_str("&gt;"),
            '_' if reads_as_escape(&bytes[i..]) => xml.push_str("_x005F_"),
            '\t' | '\n' => xml.push(c),
            c if u32::from(c) < 0x20 || c == '\u{FFFE}' || c == '\u{FFFF}' => {
                let _ = write!(xml, "_x{:04X}_", u32::from(c));
            }
            c => xml.push(c),
        }
    }
}

/// Append `value` to `xml` as an attribute's value.
fn push_attribute(xml: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '&' => xml.push_str("&amp;"),
            '<' => xml.push_str("&lt;"),
            '>' => xml.push_str("&gt;"),
            '"' => xml.push_str("&quot;"),
            c => xml.push(c),
        }
    }
}

/// Append an inline string cell holding `value` in column `letters` of
/// `row`, in style `style` (0 plain, 1 bold).
fn push_cell(xml: &mut String, letters: &str, row: u32, style: u8, value: &str) {
    let _ = write!(xml, "<c r=\"{letters}{row}\"");
    if style != 0 {
        let _ = write!(xml, " s=\"{style}\"");
    }
    xml.push_str(" t=\"inlineStr\"><is>");
    // Without this, a reader may drop the text's leading and trailing spaces.
    if value.starts_with(char::is_whitespace) || value.ends_with(char::is_whitespace) {
        xml.push_str("<t xml:space=\"preserve\">");
    } else {
        xml.push_str("<t>");
    }
    push_text(xml, value);
    xml.push_str("</t></is></c>");
}

const XML_DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n";
const MAIN: &str = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const RELATIONSHIPS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
const DOCUMENT_RELATIONSHIPS: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships";

/// The parts of an XLSX file other than its worksheet, by name.
fn package_parts(sheet: &str) -> [(&'static str, String); 5] {
    let mut name = String::new();
    push_attribute(&mut name, sheet);
    [
        (
            "[Content_Types].xml",
            format!(
                "{XML_DECLARATION}<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
                 <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
                 <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
                 <Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>\
                 <Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>\
                 <Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/>\
                 </Types>"
            ),
        ),
        (
            "_rels/.rels",
            format!(
                "{XML_DECLARATION}<Relationships xmlns=\"{RELATIONSHIPS}\">\
                 <Relationship Id=\"rId1\" Type=\"{DOCUMENT_RELATIONSHIPS}/officeDocument\" Target=\"xl/workbook.xml\"/>\
                 </Relationships>"
            ),
        ),
        (
            "xl/workbook.xml",
            format!(
                "{XML_DECLARATION}<workbook xmlns=\"{MAIN}\" xmlns:r=\"{DOCUMENT_RELATIONSHIPS}\">\
                 <bookViews><workbookView/></bookViews>\
                 <sheets><sheet name=\"{name}\" sheetId=\"1\" r:id=\"rId1\"/></sheets>\
                 </workbook>"
            ),
        ),
        (
            "xl/_rels/workbook.xml.rels",
            format!(
                "{XML_DECLARATION}<Relationships xmlns=\"{RELATIONSHIPS}\">\
                 <Relationship Id=\"rId1\" Type=\"{DOCUMENT_RELATIONSHIPS}/worksheet\" Target=\"worksheets/sheet1.xml\"/>\
                 <Relationship Id=\"rId2\" Type=\"{DOCUMENT_RELATIONSHIPS}/styles\" Target=\"styles.xml\"/>\
                 </Relationships>"
            ),
        ),
        (
            // Style 0 is plain text, style 1 the header's bold.
            "xl/styles.xml",
            format!(
                "{XML_DECLARATION}<styleSheet xmlns=\"{MAIN}\">\
                 <fonts count=\"2\">\
                 <font><sz val=\"11\"/><name val=\"Calibri\"/><family val=\"2\"/></font>\
                 <font><b/><sz val=\"11\"/><name val=\"Calibri\"/><family val=\"2\"/></font>\
                 </fonts>\
                 <fills count=\"2\"><fill><patternFill patternType=\"none\"/></fill><fill><patternFill patternType=\"gray125\"/></fill></fills>\
                 <borders count=\"1\"><border><left/><right/><top/><bottom/><diagonal/></border></borders>\
                 <cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs>\
                 <cellXfs count=\"2\">\
                 <xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/>\
                 <xf numFmtId=\"0\" fontId=\"1\" fillId=\"0\" borderId=\"0\" xfId=\"0\" applyFont=\"1\"/>\
                 </cellXfs>\
                 <cellStyles count=\"1\"><cellStyle name=\"Normal\" xfId=\"0\" builtinId=\"0\"/></cellStyles>\
                 </styleSheet>"
            ),
        ),
    ]
}

/// A file being written, a row at a time.
pub enum Writer {
    Csv {
        csv: Box<csv::Writer<Bounded>>,
        refusal: Refusal,
        max: usize,
    },
    Xlsx(Box<Xlsx>),
}

/// An XLSX file whose worksheet is being written: each row's XML is
/// compressed into the file as it's written.
pub struct Xlsx {
    zip: ZipWriter<Bounded>,
    refusal: Refusal,
    max: usize,
    stop: Stop,
    /// Each column's letters.
    columns: Vec<String>,
    /// The last row written: the header is row 1.
    row: u32,
    /// The row being written, reused from row to row.
    xml: String,
}

impl Xlsx {
    fn new(sheet: &str, headers: &[&str], max: usize, stop: &Stop) -> Result<Self, ExportError> {
        let out = Bounded::new(max, stop.clone());
        let refusal = out.refusal.clone();
        let mut zip = ZipWriter::new(out);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .last_modified_time(DateTime::default());
        for (name, content) in package_parts(&sheet_name(sheet)) {
            zip.start_file(name, options)
                .map_err(|e| refusal.error(max, e))?;
            zip.write_all(content.as_bytes())
                .map_err(|e| refusal.error(max, e))?;
        }
        zip.start_file("xl/worksheets/sheet1.xml", options)
            .map_err(|e| refusal.error(max, e))?;
        let columns: Vec<String> = (0..headers.len()).map(column_letters).collect();
        let mut xml = format!(
            "{XML_DECLARATION}<worksheet xmlns=\"{MAIN}\">\
             <sheetViews><sheetView tabSelected=\"1\" workbookViewId=\"0\">\
             <pane ySplit=\"1\" topLeftCell=\"A2\" activePane=\"bottomLeft\" state=\"frozen\"/>\
             <selection pane=\"bottomLeft\" activeCell=\"A2\" sqref=\"A2\"/>\
             </sheetView></sheetViews><cols>"
        );
        for (i, header) in headers.iter().enumerate() {
            let width = header.chars().count().clamp(8, 48) + 2;
            let _ = write!(
                xml,
                "<col min=\"{n}\" max=\"{n}\" width=\"{width}\" customWidth=\"1\"/>",
                n = i + 1
            );
        }
        xml.push_str("</cols><sheetData><row r=\"1\">");
        for (letters, header) in columns.iter().zip(headers) {
            push_cell(&mut xml, letters, 1, 1, header);
        }
        xml.push_str("</row>");
        let mut xlsx = Self {
            zip,
            refusal,
            max,
            stop: stop.clone(),
            columns,
            row: 1,
            xml,
        };
        xlsx.flush_xml()?;
        Ok(xlsx)
    }

    /// Compress the XML written so far into the file.
    fn flush_xml(&mut self) -> Result<(), ExportError> {
        let written = self.zip.write_all(self.xml.as_bytes());
        self.xml.clear();
        written.map_err(|e| self.refusal.error(self.max, e))
    }

    fn row(&mut self, cells: &[Option<String>]) -> Result<(), ExportError> {
        if self.row == MAX_SHEET_ROWS {
            return Err(ExportError::TooLarge(format!(
                "more rows than an XLSX worksheet holds ({})",
                MAX_SHEET_ROWS - 1
            )));
        }
        self.row += 1;
        if self.row.is_multiple_of(STOP_EVERY) && self.stop.stopped() {
            return Err(ExportError::Stopped);
        }
        let row = self.row;
        let _ = write!(self.xml, "<row r=\"{row}\">");
        for (letters, cell) in self.columns.iter().zip(cells) {
            // An empty cell is left out.
            let Some(value) = cell.as_deref().filter(|v| !v.is_empty()) else {
                continue;
            };
            if value.len() > MAX_CELL_CHARS && value.encode_utf16().count() > MAX_CELL_CHARS {
                return Err(ExportError::TooLarge(format!(
                    "a cell is longer than an XLSX file allows ({MAX_CELL_CHARS} characters); export CSV instead"
                )));
            }
            push_cell(&mut self.xml, letters, row, 0, value);
        }
        self.xml.push_str("</row>");
        self.flush_xml()
    }

    fn finish(mut self) -> Result<Vec<u8>, ExportError> {
        self.xml.push_str("</sheetData>");
        if self.row > 1 {
            // Identifiers such as 000123 are text on purpose: don't flag them.
            let last = self.columns.last().map_or("A", String::as_str);
            let _ = write!(
                self.xml,
                "<ignoredErrors><ignoredError sqref=\"A2:{last}{}\" numberStoredAsText=\"1\"/></ignoredErrors>",
                self.row
            );
        }
        self.xml.push_str("</worksheet>");
        self.flush_xml()?;
        let (refusal, max) = (self.refusal.clone(), self.max);
        let out = self.zip.finish().map_err(|e| refusal.error(max, e))?;
        Ok(out.out.into_inner())
    }
}

impl Writer {
    /// A file of `format` holding `def`'s output headers, in order.
    pub fn new(
        format: Format,
        def: &Definition,
        max_bytes: usize,
        stop: &Stop,
    ) -> Result<Self, ExportError> {
        let headers: Vec<&str> = def
            .output
            .iter()
            .map(|name| {
                def.column(name)
                    .map_or(name.as_str(), |c| c.header.as_str())
            })
            .collect();
        match format {
            Format::Csv => {
                let mut out = Bounded::new(max_bytes, stop.clone());
                let refusal = out.refusal.clone();
                // A byte order mark, so spreadsheets read the file as UTF-8.
                out.write_all("\u{feff}".as_bytes())
                    .map_err(|e| refusal.error(max_bytes, e))?;
                let mut csv = csv::WriterBuilder::new()
                    .terminator(csv::Terminator::CRLF)
                    .quote_style(csv::QuoteStyle::Necessary)
                    .from_writer(out);
                for header in headers {
                    csv.write_field(neutralise(header).as_bytes())
                        .map_err(|e| refusal.error(max_bytes, e))?;
                }
                csv.write_record(None::<&[u8]>)
                    .map_err(|e| refusal.error(max_bytes, e))?;
                Ok(Self::Csv {
                    csv: Box::new(csv),
                    refusal,
                    max: max_bytes,
                })
            }
            Format::Xlsx => Ok(Self::Xlsx(Box::new(Xlsx::new(
                &def.display_name,
                &headers,
                max_bytes,
                stop,
            )?))),
        }
    }

    /// Write one row's cells.
    pub fn row(&mut self, cells: &[Option<String>]) -> Result<(), ExportError> {
        match self {
            Self::Csv { csv, refusal, max } => {
                for cell in cells {
                    let value = cell.as_deref().map_or(Cow::Borrowed(""), neutralise);
                    csv.write_field(value.as_bytes())
                        .map_err(|e| refusal.error(*max, e))?;
                }
                csv.write_record(None::<&[u8]>)
                    .map_err(|e| refusal.error(*max, e))
            }
            Self::Xlsx(xlsx) => xlsx.row(cells),
        }
    }

    /// The whole file.
    pub fn finish(self) -> Result<Vec<u8>, ExportError> {
        match self {
            Self::Csv { csv, refusal, max } => {
                let out = csv
                    .into_inner()
                    .map_err(|e| refusal.error(max, e.error()))?;
                Ok(out.out.into_inner())
            }
            Self::Xlsx(xlsx) => xlsx.finish(),
        }
    }
}

/// How many rows `query` matches in `table`, or [`ExportError::TooManyRows`]
/// if that's more than `limits` allow.
pub fn count(
    table: &Table,
    def: &Definition,
    query: &Query,
    limits: Limits,
    stop: &Stop,
) -> Result<u64, ExportError> {
    let matched = table.count(def, query, stop)?;
    if matched > limits.max_rows {
        return Err(ExportError::TooManyRows {
            matched,
            max: limits.max_rows,
        });
    }
    Ok(matched)
}

/// The file of `format` holding every row `query` matches in `table`, and
/// how many rows it holds.
pub fn write(
    table: &Table,
    def: &Definition,
    query: &Query,
    format: Format,
    limits: Limits,
    stop: &Stop,
) -> Result<(Vec<u8>, u64), ExportError> {
    let mut writer = Writer::new(format, def, limits.max_bytes, stop)?;
    let mut written = 0;
    let rows = table.each_row(def, query, stop, |cells| {
        written += 1;
        if written > limits.max_rows {
            return Err(ExportError::TooManyRows {
                matched: written,
                max: limits.max_rows,
            });
        }
        writer.row(cells)
    })?;
    Ok((writer.finish()?, rows))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::{Cursor, Read};

    use std::time::Instant;

    use calamine::{open_workbook_from_rs, Data, Reader};

    use super::*;
    use crate::analysis::definition::tests::awards_report;
    use crate::analysis::query::QueryRequest;
    use crate::analysis::table::Scope;

    pub(crate) fn soon() -> Stop {
        Stop::after(Duration::from_secs(60))
    }

    /// The whole export of `query` from `table` in `format`, as the worker
    /// makes it: counted, then written.
    pub(crate) fn export(
        table: &Table,
        def: &Definition,
        query: &Query,
        format: Format,
        limits: Limits,
        stop: &Stop,
    ) -> Result<(Vec<u8>, u64), ExportError> {
        count(table, def, query, limits, stop)?;
        write(table, def, query, format, limits, stop)
    }

    /// An upload of `rows` under `def`'s headers, quoted as a CSV needs.
    pub(crate) fn upload(def: &Definition, rows: &[Vec<String>]) -> Vec<u8> {
        let mut csv = csv::Writer::from_writer(Vec::new());
        csv.write_record(def.columns.iter().map(|c| c.header.as_str()))
            .unwrap();
        for row in rows {
            csv.write_record(row).unwrap();
        }
        csv.into_inner().unwrap()
    }

    /// The query `json` asks for.
    pub(crate) fn query(def: &Definition, json: serde_json::Value) -> Query {
        let request: QueryRequest = serde_json::from_value(json).unwrap();
        Query::check(def, &request).unwrap()
    }

    /// A CSV export's header and rows, as a reader parses them.
    pub(crate) fn read_csv(bytes: &[u8]) -> Vec<Vec<String>> {
        let text = std::str::from_utf8(bytes).unwrap();
        let text = text.strip_prefix('\u{feff}').expect("a byte order mark");
        csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(text.as_bytes())
            .records()
            .map(|r| r.unwrap().iter().map(String::from).collect())
            .collect()
    }

    /// An XLSX export's header and rows, every cell a string or empty; any
    /// other kind of cell, a formula or a link fails.
    pub(crate) fn read_xlsx(bytes: &[u8]) -> Vec<Vec<String>> {
        let mut book: calamine::Xlsx<_> = open_workbook_from_rs(Cursor::new(bytes)).unwrap();
        let names = book.sheet_names();
        assert_eq!(names.len(), 1);
        assert!(book.worksheet_formula(&names[0]).unwrap().is_empty());
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        let mut sheet = String::new();
        archive
            .by_name("xl/worksheets/sheet1.xml")
            .unwrap()
            .read_to_string(&mut sheet)
            .unwrap();
        assert!(!sheet.contains("<f>") && !sheet.contains("<f "));
        assert!(!sheet.contains("<hyperlink"));
        assert!(archive
            .by_name("xl/worksheets/_rels/sheet1.xml.rels")
            .is_err());
        let range = book.worksheet_range(&names[0]).unwrap();
        assert_eq!(range.start(), Some((0, 0)));
        range
            .rows()
            .map(|row| {
                row.iter()
                    .map(|cell| match cell {
                        Data::String(s) => s.clone(),
                        Data::Empty => String::new(),
                        other => panic!("a cell that isn't text: {other:?}"),
                    })
                    .collect()
            })
            .collect()
    }

    /// Awards rows whose values a spreadsheet could misread.
    fn awkward() -> Vec<Vec<String>> {
        let row = |staff: &str, first: &str, surname: &str, award: &str, date: &str| {
            [
                staff,
                "M001",
                "Mx",
                first,
                surname,
                "01/01/1990",
                "Bank A",
                "Group A",
                award,
                "",
                date,
            ]
            .map(String::from)
            .to_vec()
        };
        vec![
            row("000123", "Zoë", "Ångström", "=1+1", "01/01/2026"),
            row("001", "Łukasz", "日本", "-2+3", "02/01/2026"),
            row("", "Alex", "Alpha \"Al\", Jr", "@SUM(A1)", "03/01/2026"),
            row("0042", "Line\nbreak", "Tab\there", "+cmd|' /C calc'!A0", ""),
            row("7", "-€1,234.50", "€-12.50", "-25.00", "04/01/2026"),
            row(
                "8",
                "https://example.invalid/x",
                "_x0041_",
                "Award A",
                "05/01/2026",
            ),
            row("9", "\u{1}control", "two  spaces", "+353", "06/01/2026"),
        ]
    }

    fn table(def: &Definition, rows: &[Vec<String>]) -> Table {
        Table::build(def, &[&upload(def, rows)], &Scope::All, &soon()).unwrap()
    }

    #[test]
    fn formulas_are_neutralised_and_amounts_kept() {
        for formula in [
            "=1+1",
            "-2+3",
            "+cmd|' /C calc'!A0",
            "@SUM(A1)",
            "\t=1",
            "\r=1",
            "-",
            "--5",
            "-1,23",
            "-1.2.3",
            "-€",
            "-1,234,56",
            "-1234,567",
            "+-5",
            "-€-5",
        ] {
            assert_eq!(neutralise(formula), format!("'{formula}"), "{formula:?}");
        }
        for kept in [
            "-25.00",
            "-€1,234.50",
            "€-12.50",
            "+353",
            "-0",
            "-1,234,567.89",
            "+£5",
            "-$1",
            "0.00",
            "Award A",
            "€5",
            "€-",
            " =1",
            "",
        ] {
            assert_eq!(neutralise(kept), kept, "{kept:?}");
        }
    }

    #[test]
    fn a_csv_export_round_trips_every_value_with_formulas_neutralised() {
        let def = awards_report();
        let rows = awkward();
        let table = table(&def, &rows);
        let sorted = query(
            &def,
            serde_json::json!({"sort": {"field": "staff_number", "direction": "asc"}}),
        );
        let (bytes, count) = export(
            &table,
            &def,
            &sorted,
            Format::Csv,
            Limits::default(),
            &soon(),
        )
        .unwrap();
        assert_eq!(count, 7);
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.starts_with("\u{feff}Staff Number,Membership Number,"));
        assert!(text.contains("\r\n"));
        let read = read_csv(&bytes);
        assert_eq!(
            read[0],
            def.output
                .iter()
                .map(|c| def.column(c).unwrap().header.clone())
                .collect::<Vec<_>>()
        );
        // Text sorts case-insensitively, a blank first; each cell is as
        // stored, but for a formula's leading quote.
        let staff: Vec<&str> = read[1..].iter().map(|r| r[0].as_str()).collect();
        assert_eq!(staff, ["", "000123", "001", "0042", "7", "8", "9"]);
        let by_staff = |staff: &str| read.iter().find(|r| r[0] == staff).unwrap();
        assert_eq!(by_staff("000123")[3..5], ["Zoë", "Ångström"]);
        assert_eq!(by_staff("000123")[8], "'=1+1");
        assert_eq!(by_staff("001")[8], "'-2+3");
        assert_eq!(by_staff("")[4], "Alpha \"Al\", Jr");
        assert_eq!(by_staff("")[8], "'@SUM(A1)");
        assert_eq!(by_staff("0042")[3..5], ["Line\nbreak", "Tab\there"]);
        assert_eq!(by_staff("0042")[8], "'+cmd|' /C calc'!A0");
        assert_eq!(by_staff("0042")[10], "");
        assert_eq!(by_staff("7")[3..5], ["-€1,234.50", "€-12.50"]);
        assert_eq!(by_staff("7")[8], "-25.00");
        assert_eq!(by_staff("7")[9], "");
        assert_eq!(by_staff("7")[10], "04/01/2026");
        assert_eq!(
            by_staff("8")[3..5],
            ["https://example.invalid/x", "_x0041_"]
        );
        assert_eq!(by_staff("9")[3..5], ["\u{1}control", "two  spaces"]);
        assert_eq!(by_staff("9")[8], "+353");
    }

    #[test]
    fn an_xlsx_export_holds_every_value_as_literal_text() {
        let def = awards_report();
        let rows = awkward();
        let table = table(&def, &rows);
        let sorted = query(
            &def,
            serde_json::json!({"sort": {"field": "exam_board_date", "direction": "desc"}}),
        );
        let (bytes, count) = export(
            &table,
            &def,
            &sorted,
            Format::Xlsx,
            Limits::default(),
            &soon(),
        )
        .unwrap();
        assert_eq!(count, 7);
        let read = read_xlsx(&bytes);
        assert_eq!(read.len(), 8);
        assert_eq!(read[0][0], "Staff Number");
        // Newest first, then the blank date.
        let dates: Vec<&str> = read[1..].iter().map(|r| r[10].as_str()).collect();
        assert_eq!(
            dates,
            [
                "06/01/2026",
                "05/01/2026",
                "04/01/2026",
                "03/01/2026",
                "02/01/2026",
                "01/01/2026",
                ""
            ]
        );
        let mut expected: Vec<Vec<String>> = rows.clone();
        expected.sort_by(|a, b| {
            let key = |r: &Vec<String>| crate::analysis::dates::to_sql(&r[10]).unwrap_or_default();
            key(b).cmp(&key(a))
        });
        assert_eq!(read[1..], expected[..]);
    }

    #[test]
    fn an_empty_result_is_the_header_alone() {
        let def = awards_report();
        let table = table(&def, &awkward());
        let none = query(
            &def,
            serde_json::json!({"filters": {"award": {"mode": "selected", "values": ["Missing"]}}}),
        );
        let (csv, rows) =
            export(&table, &def, &none, Format::Csv, Limits::default(), &soon()).unwrap();
        assert_eq!(rows, 0);
        assert_eq!(read_csv(&csv).len(), 1);
        let (xlsx, _) = export(
            &table,
            &def,
            &none,
            Format::Xlsx,
            Limits::default(),
            &soon(),
        )
        .unwrap();
        assert_eq!(read_xlsx(&xlsx).len(), 1);
    }

    #[test]
    fn an_export_over_a_limit_fails_whole() {
        let def = awards_report();
        let table = table(&def, &awkward());
        let all = query(&def, serde_json::json!({}));
        for format in [Format::Csv, Format::Xlsx] {
            let rows = Limits {
                max_rows: 6,
                ..Limits::default()
            };
            assert_eq!(
                export(&table, &def, &all, format, rows, &soon()).unwrap_err(),
                ExportError::TooManyRows { matched: 7, max: 6 }
            );
            let bytes = Limits {
                max_bytes: 512,
                ..Limits::default()
            };
            assert!(matches!(
                export(&table, &def, &all, format, bytes, &soon()).unwrap_err(),
                ExportError::TooLarge(_)
            ));
            let stopped = Stop::after(Duration::ZERO);
            assert_eq!(
                export(&table, &def, &all, format, Limits::default(), &stopped).unwrap_err(),
                ExportError::Stopped
            );
        }
        // A write that comes once the stop has fired is refused.
        let stop = soon();
        let mut out = Bounded::new(1 << 20, stop.clone());
        out.write_all(b"before").unwrap();
        stop.abandon();
        assert!(out.write_all(b"after").is_err());
        assert_eq!(out.refusal.error(1 << 20, "x"), ExportError::Stopped);
        assert_eq!(out.out.get_ref(), b"before");
        // As is one that would take the file past its limit, even when it
        // goes back to overwrite.
        let mut out = Bounded::new(8, soon());
        out.write_all(b"12345678").unwrap();
        out.seek(SeekFrom::Start(4)).unwrap();
        out.write_all(b"abcd").unwrap();
        assert!(out.write_all(b"e").is_err());
        assert!(matches!(
            out.refusal.error(8, "x"),
            ExportError::TooLarge(_)
        ));
        assert_eq!(out.out.get_ref(), b"1234abcd");
    }

    #[test]
    fn xlsx_text_reads_back_exactly() {
        let mut xml = String::new();
        push_text(&mut xml, "a&b<c>d \"e\" _x0041_ _x00_ \u{1}\r\n\t\u{FFFF}");
        assert_eq!(
            xml,
            "a&amp;b&lt;c&gt;d \"e\" _x005F_x0041_ _x00_ _x0001__x000D_\n\t_xFFFF_"
        );
        let names: Vec<String> = [0, 25, 26, 32, 51, 52, 701, 702]
            .into_iter()
            .map(column_letters)
            .collect();
        assert_eq!(names, ["A", "Z", "AA", "AG", "AZ", "BA", "ZZ", "AAA"]);
    }

    #[test]
    fn an_xlsx_cell_longer_than_excel_allows_is_refused() {
        let def = awards_report();
        let mut rows = awkward();
        rows[0][3] = "x".repeat(MAX_CELL_CHARS + 1);
        let table = table(&def, &rows);
        let all = query(&def, serde_json::json!({}));
        assert!(matches!(
            export(&table, &def, &all, Format::Xlsx, Limits::default(), &soon()).unwrap_err(),
            ExportError::TooLarge(message) if message.contains("CSV")
        ));
        // A CSV holds it.
        export(&table, &def, &all, Format::Csv, Limits::default(), &soon()).unwrap();
    }

    #[test]
    fn worksheet_names_keep_what_excel_allows() {
        assert_eq!(sheet_name("Awards Report"), "Awards Report");
        assert_eq!(sheet_name("A/B: [C]*?\\"), "AB C");
        assert_eq!(sheet_name(&"x".repeat(40)), "x".repeat(31));
        assert_eq!(sheet_name("'quoted'"), "quoted");
        assert_eq!(sheet_name("[]"), "Export");
        assert_eq!(sheet_name("History"), "Export");
    }

    /// A row of the pilot's widest report, the CPD report: 33 columns, a
    /// tenth of its optional cells blank.
    fn wide_row(def: &Definition, i: usize) -> Vec<String> {
        const FIRST: [&str; 8] = ["Alex", "Sam", "Zoë", "Łukasz", "Niamh", "Seán", "Jo", "Kim"];
        def.columns
            .iter()
            .enumerate()
            .map(|(c, column)| {
                if (i + c).is_multiple_of(10) && c > 1 {
                    return String::new();
                }
                match column.name.as_str() {
                    "staff_number" => format!("{i:06}"),
                    "membership_number" => format!("M{:06}", i % 60_000),
                    "title" => ["Mx", "Ms", "Mr", "Dr"][i % 4].into(),
                    "first_name" => FIRST[i % FIRST.len()].into(),
                    "surname" => format!("Surname {}", i % 5000),
                    "employer" => format!("Bank {}", i % 40),
                    "employer_group" => format!("Group {}", i % 8),
                    _ if column.kind == crate::analysis::definition::ColumnType::Date => {
                        format!(
                            "{:02}/{:02}/{}",
                            1 + i % 28,
                            1 + (i + c) % 12,
                            1990 + (i + c) % 36
                        )
                    }
                    name if name.contains("hours") || name.contains("shortfall") => {
                        format!("{}.{}", (i + c) % 60, i % 10)
                    }
                    name => format!("{name} {}", (i + c) % 25),
                }
            })
            .collect()
    }

    /// The pilot's scale: 100,000 rows of the CPD report's 33 columns,
    /// exported whole, in each format in a process of its own, with the time
    /// it takes, the file's size and the most memory it held at once. Run by
    /// `just scale`.
    fn measure_a_pilot_sized_export(format: Format) {
        const ROWS: usize = 100_000;
        let def =
            Definition::parse(include_bytes!("../../drt-examples/cpd-report-v1.toml")).unwrap();
        assert_eq!(def.output.len(), 33);
        let rows: Vec<Vec<String>> = (0..ROWS).map(|i| wide_row(&def, i)).collect();
        let csv = upload(&def, &rows);
        drop(rows);
        let table = Table::build(&def, &[&csv], &Scope::All, &soon()).unwrap();
        let upload_bytes = csv.len();
        drop(csv);
        let all = query(&def, serde_json::json!({}));

        let before = crate::heap::start();
        let started = Instant::now();
        let (bytes, written) =
            export(&table, &def, &all, format, Limits::default(), &soon()).unwrap();
        let took = started.elapsed();
        let peak = crate::heap::peak() - before;

        assert_eq!(written, ROWS as u64);
        println!(
            "{format:?}: {ROWS} rows x {} columns ({:.1} MiB as uploaded): \
             {:.2} s, {:.1} MiB file, {:.1} MiB held at most",
            def.output.len(),
            upload_bytes as f64 / 1048576.0,
            took.as_secs_f64(),
            bytes.len() as f64 / 1048576.0,
            peak as f64 / 1048576.0,
        );
        assert!(bytes.len() <= MAX_BYTES);
        assert!(took < crate::analysis::runner::DEADLINE);
    }

    #[test]
    #[ignore = "pilot scale, slow in unoptimised builds: run `just scale`"]
    fn a_pilot_sized_csv_export() {
        measure_a_pilot_sized_export(Format::Csv);
    }

    #[test]
    #[ignore = "pilot scale, slow in unoptimised builds: run `just scale`"]
    fn a_pilot_sized_xlsx_export() {
        measure_a_pilot_sized_export(Format::Xlsx);
    }
}
