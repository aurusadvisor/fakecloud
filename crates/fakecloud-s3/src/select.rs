//! S3 SelectObjectContent query engine (basic).
//!
//! Supports CSV input/output and a minimal SQL dialect:
//!   SELECT * FROM s3object
//!   SELECT col1, col2 FROM s3object
//!   SELECT * FROM s3object WHERE col = 'val'
//!   SELECT * FROM s3object WHERE col = 123
//!   SELECT * FROM s3object WHERE col LIKE 'prefix%'

use serde::Deserialize;

// ── XML request shapes ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename = "SelectObjectContentRequest")]
pub struct SelectRequest {
    pub Expression: String,
    pub ExpressionType: String,
    pub InputSerialization: InputSerialization,
    pub OutputSerialization: OutputSerialization,
}

#[derive(Debug, Deserialize, Default)]
pub struct InputSerialization {
    pub CSV: Option<CsvInput>,
    pub JSON: Option<JsonInput>,
    #[serde(rename = "CompressionType")]
    pub compression_type: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct CsvInput {
    #[serde(rename = "FileHeaderInfo")]
    pub file_header_info: Option<String>,
    #[serde(rename = "RecordDelimiter")]
    pub record_delimiter: Option<String>,
    #[serde(rename = "FieldDelimiter")]
    pub field_delimiter: Option<String>,
    #[serde(rename = "QuoteCharacter")]
    pub quote_character: Option<String>,
    #[serde(rename = "QuoteEscapeCharacter")]
    pub quote_escape_character: Option<String>,
    #[serde(rename = "Comments")]
    pub comments: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct JsonInput {
    #[serde(rename = "Type")]
    pub json_type: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct OutputSerialization {
    pub CSV: Option<CsvOutput>,
    pub JSON: Option<JsonOutput>,
}

#[derive(Debug, Deserialize, Default)]
pub struct CsvOutput {
    #[serde(rename = "QuoteFields")]
    pub quote_fields: Option<String>,
    #[serde(rename = "RecordDelimiter")]
    pub record_delimiter: Option<String>,
    #[serde(rename = "FieldDelimiter")]
    pub field_delimiter: Option<String>,
    #[serde(rename = "QuoteCharacter")]
    pub quote_character: Option<String>,
    #[serde(rename = "QuoteEscapeCharacter")]
    pub quote_escape_character: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct JsonOutput {
    #[serde(rename = "RecordDelimiter")]
    pub record_delimiter: Option<String>,
}

// ── SQL evaluator ─────────────────────────────────────────────────

#[derive(Debug)]
pub enum SqlSelect {
    All,
    Columns(Vec<String>),
}

#[derive(Debug)]
pub enum WhereClause {
    Eq(String, LiteralValue),
    Like(String, String),
}

#[derive(Debug, Clone)]
pub enum LiteralValue {
    String(String),
    Number(f64),
}

#[derive(Debug)]
pub struct Query {
    pub select: SqlSelect,
    pub from: String,
    pub where_clause: Option<WhereClause>,
}

/// Parse a minimal SELECT statement. Errors are static strings for
/// simplicity — callers map them to AWS error codes.
pub fn parse_sql(sql: &str) -> Result<Query, &'static str> {
    let sql = sql.trim();
    let upper = sql.to_uppercase();

    if !upper.starts_with("SELECT ") {
        return Err("expected SELECT");
    }

    let from_pos = upper.find(" FROM ").ok_or("expected FROM")?;
    let select_part = sql[7..from_pos].trim();

    let rest = &sql[from_pos + 6..];
    let where_pos = rest.to_uppercase().find(" WHERE ");

    let (from, where_clause) = match where_pos {
        Some(wp) => {
            let from = rest[..wp].trim().to_string();
            let where_str = rest[wp + 7..].trim();
            (from, Some(parse_where(where_str)?))
        }
        None => (rest.trim().to_string(), None),
    };

    let select = if select_part.eq_ignore_ascii_case("*") {
        SqlSelect::All
    } else {
        let cols: Vec<String> = select_part
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        SqlSelect::Columns(cols)
    };

    Ok(Query {
        select,
        from,
        where_clause,
    })
}

fn parse_where(s: &str) -> Result<WhereClause, &'static str> {
    let upper = s.to_uppercase();
    // LIKE
    if let Some(pos) = upper.find(" LIKE ") {
        let col = s[..pos].trim().to_string();
        let pattern = s[pos + 6..].trim();
        let pat = strip_quotes(pattern).unwrap_or(pattern).to_string();
        return Ok(WhereClause::Like(col, pat));
    }
    // =
    if let Some(pos) = s.find('=') {
        let col = s[..pos].trim().to_string();
        let val_str = s[pos + 1..].trim();
        let val = if val_str.starts_with('\'') && val_str.ends_with('\'') {
            LiteralValue::String(strip_quotes(val_str).unwrap_or(val_str).to_string())
        } else {
            LiteralValue::Number(val_str.parse().map_err(|_| "invalid number")?)
        };
        return Ok(WhereClause::Eq(col, val));
    }
    Err("unsupported WHERE clause")
}

fn strip_quotes(s: &str) -> Option<&str> {
    if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
        Some(&s[1..s.len() - 1])
    } else {
        None
    }
}

// ── CSV parser ──────────────────────────────────────────────────────

/// Parse CSV bytes into an optional header row and data rows.
pub fn parse_csv(
    input: &[u8],
    has_header: bool,
    field_delimiter: char,
    record_delimiter: char,
) -> (Option<Vec<String>>, Vec<Vec<String>>) {
    let text = String::from_utf8_lossy(input);
    let mut headers = None;
    let mut rows = Vec::new();

    for line in text.split(record_delimiter) {
        if line.is_empty() {
            continue;
        }
        let fields: Vec<String> = line.split(field_delimiter).map(|s| s.to_string()).collect();
        if headers.is_none() && has_header {
            headers = Some(fields);
        } else {
            rows.push(fields);
        }
    }

    (headers, rows)
}

// ── JSON parser (newline-delimited) ─────────────────────────────────

/// Parse newline-delimited JSON into rows.
/// Each line must be a JSON object; keys become headers on the first row.
pub fn parse_json_lines(input: &[u8]) -> (Option<Vec<String>>, Vec<Vec<String>>) {
    let text = String::from_utf8_lossy(input);
    let mut headers: Option<Vec<String>> = None;
    let mut rows = Vec::new();

    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let serde_json::Value::Object(map) = val else {
            continue;
        };
        if headers.is_none() {
            let keys: Vec<String> = map.keys().cloned().collect();
            headers = Some(keys.clone());
        }
        let row: Vec<String> = headers
            .as_ref()
            .unwrap()
            .iter()
            .map(|k| {
                map.get(k)
                    .map(|v| match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .unwrap_or_default()
            })
            .collect();
        rows.push(row);
    }

    (headers, rows)
}

// ── Query evaluation ────────────────────────────────────────────────

/// Evaluate a parsed query against parsed rows.
pub fn evaluate_query(
    query: &Query,
    headers: &Option<Vec<String>>,
    rows: &[Vec<String>],
) -> Vec<Vec<String>> {
    let mut result = Vec::new();

    for row in rows {
        if !matches_where(query.where_clause.as_ref(), headers, row) {
            continue;
        }
        let out_row = match &query.select {
            SqlSelect::All => row.clone(),
            SqlSelect::Columns(cols) => {
                let mut out = Vec::with_capacity(cols.len());
                for col in cols {
                    if let Some(idx) = header_index(headers, col) {
                        out.push(row.get(idx).cloned().unwrap_or_default());
                    } else {
                        out.push(String::new());
                    }
                }
                out
            }
        };
        result.push(out_row);
    }

    result
}

fn header_index(headers: &Option<Vec<String>>, col: &str) -> Option<usize> {
    headers
        .as_ref()?
        .iter()
        .position(|h| h.eq_ignore_ascii_case(col))
}

fn matches_where(
    clause: Option<&WhereClause>,
    headers: &Option<Vec<String>>,
    row: &[String],
) -> bool {
    let Some(clause) = clause else {
        return true;
    };
    let idx = match header_index(headers, col_name(clause)) {
        Some(i) => i,
        None => return false,
    };
    let cell = row.get(idx).cloned().unwrap_or_default();
    match clause {
        WhereClause::Eq(_, val) => match val {
            LiteralValue::String(s) => cell == *s,
            LiteralValue::Number(n) => cell.parse::<f64>().map(|c| c == *n).unwrap_or(false),
        },
        WhereClause::Like(_, pat) => {
            if pat.ends_with('%') {
                let prefix = &pat[..pat.len() - 1];
                cell.starts_with(prefix)
            } else {
                cell == *pat
            }
        }
    }
}

fn col_name(clause: &WhereClause) -> &str {
    match clause {
        WhereClause::Eq(col, _) | WhereClause::Like(col, _) => col.as_str(),
    }
}

// ── Output formatters ───────────────────────────────────────────────

/// Format rows as CSV bytes.
pub fn format_csv(rows: &[Vec<String>], field_delimiter: &str, record_delimiter: &str) -> Vec<u8> {
    let mut out = String::new();
    for row in rows {
        for (i, field) in row.iter().enumerate() {
            if i > 0 {
                out.push_str(field_delimiter);
            }
            out.push_str(field);
        }
        out.push_str(record_delimiter);
    }
    out.into_bytes()
}

/// Format rows as newline-delimited JSON bytes.
pub fn format_json_lines(rows: &[Vec<String>], headers: &Option<Vec<String>>) -> Vec<u8> {
    let mut out = String::new();
    let hdrs = headers.as_ref().cloned().unwrap_or_default();
    for row in rows {
        let mut map = serde_json::Map::new();
        for (i, field) in row.iter().enumerate() {
            let key = hdrs.get(i).cloned().unwrap_or_else(|| format!("_{i}"));
            map.insert(key, serde_json::Value::String(field.clone()));
        }
        out.push_str(&serde_json::to_string(&serde_json::Value::Object(map)).unwrap());
        out.push('\n');
    }
    out.into_bytes()
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_select_star() {
        let q = parse_sql("SELECT * FROM s3object").unwrap();
        assert!(matches!(q.select, SqlSelect::All));
        assert_eq!(q.from, "s3object");
        assert!(q.where_clause.is_none());
    }

    #[test]
    fn parse_select_columns() {
        let q = parse_sql("SELECT a, b FROM s3object").unwrap();
        assert!(matches!(q.select, SqlSelect::Columns(cols) if cols == vec!["a", "b"]));
    }

    #[test]
    fn parse_where_eq_string() {
        let q = parse_sql("SELECT * FROM s3object WHERE name = 'alice'").unwrap();
        assert!(
            matches!(q.where_clause, Some(WhereClause::Eq(_, LiteralValue::String(ref s))) if s == "alice")
        );
    }

    #[test]
    fn parse_where_eq_number() {
        let q = parse_sql("SELECT * FROM s3object WHERE age = 30").unwrap();
        assert!(
            matches!(q.where_clause, Some(WhereClause::Eq(_, LiteralValue::Number(n))) if n == 30.0)
        );
    }

    #[test]
    fn parse_where_like() {
        let q = parse_sql("SELECT * FROM s3object WHERE name LIKE 'a%'").unwrap();
        assert!(
            matches!(q.where_clause, Some(WhereClause::Like(ref col, ref pat)) if col == "name" && pat == "a%")
        );
    }

    #[test]
    fn csv_parse_with_header() {
        let (hdrs, rows) = parse_csv(b"a,b\n1,2\n3,4", true, ',', '\n');
        assert_eq!(hdrs, Some(vec!["a".to_string(), "b".to_string()]));
        assert_eq!(rows, vec![vec!["1", "2"], vec!["3", "4"]]);
    }

    #[test]
    fn evaluate_select_all() {
        let q = parse_sql("SELECT * FROM s3object").unwrap();
        let hdrs = Some(vec!["a".to_string(), "b".to_string()]);
        let rows = vec![vec!["1".to_string(), "2".to_string()]];
        let out = evaluate_query(&q, &hdrs, &rows);
        assert_eq!(out, vec![vec!["1", "2"]]);
    }

    #[test]
    fn evaluate_where_eq() {
        let q = parse_sql("SELECT * FROM s3object WHERE a = '1'").unwrap();
        let hdrs = Some(vec!["a".to_string(), "b".to_string()]);
        let rows = vec![
            vec!["1".to_string(), "2".to_string()],
            vec!["3".to_string(), "4".to_string()],
        ];
        let out = evaluate_query(&q, &hdrs, &rows);
        assert_eq!(out, vec![vec!["1", "2"]]);
    }

    #[test]
    fn evaluate_select_columns() {
        let q = parse_sql("SELECT b FROM s3object").unwrap();
        let hdrs = Some(vec!["a".to_string(), "b".to_string()]);
        let rows = vec![vec!["1".to_string(), "2".to_string()]];
        let out = evaluate_query(&q, &hdrs, &rows);
        assert_eq!(out, vec![vec!["2"]]);
    }

    #[test]
    fn format_csv_round_trip() {
        let rows = vec![vec!["1".to_string(), "2".to_string()]];
        let bytes = format_csv(&rows, ",", "\n");
        assert_eq!(bytes, b"1,2\n");
    }
}
