//! Query language and matching.
//!
//! Text mode (default), whitespace-separated terms that must all match:
//!   `mimikatz`            any field contains "mimikatz"
//!   `"logon type"`        phrase (use `""` inside quotes for a literal quote)
//!   `-svchost`            exclude records containing "svchost"
//!   `TargetUserName:adm`  that field contains "adm"
//!   `LogonType=3`         that field equals "3" (or its decoded meaning, e.g. `LogonType=Network`)
//!   `CommandLine~"\-enc\s"` that field matches a regex
//!   `TargetUserName:`     the record has that field at all
//! Field names match the full dotted path (`Execution.ProcessID`) or its last segment
//! (`ProcessID`), case-insensitively.
//!
//! Regex mode: the whole query is one regex, run against every `Field=value` line of a record.

use std::ops::Range;

use memchr::memmem::Finder;
use regex::{Regex, RegexBuilder};

use crate::model::Record;

#[derive(Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct SearchOptions {
    pub regex: bool,
    pub case_sensitive: bool,
}

pub enum Query {
    Empty,
    Regex(Regex),
    Terms(Vec<Term>),
}

pub struct Term {
    negate: bool,
    kind: Kind,
}

enum Kind {
    Text {
        needle: String,
        finder: Finder<'static>,
    },
    Field {
        key: KeyMatch,
        op: Op,
    },
}

enum Op {
    Contains(String),
    Equals(String),
    Regex(Regex),
}

/// Which interned keys a field term applies to.
struct KeyMatch {
    /// Field names this term applies to (more than one for aliases like `process`).
    names_lc: Vec<String>,
    /// Precomputed for keys known at compile time; keys interned later are checked by name.
    known: Vec<bool>,
}

impl KeyMatch {
    fn new(name: &str, keys_lc: &[Box<str>]) -> Self {
        let names_lc: Vec<String> = alias(&name.to_lowercase());
        let known = keys_lc
            .iter()
            .map(|k| names_lc.iter().any(|n| key_matches(n, k)))
            .collect();
        Self { names_lc, known }
    }

    fn any_known(&self) -> bool {
        self.known.iter().any(|b| *b)
    }

    #[inline]
    fn matches(&self, id: u32, keys_lc: &[Box<str>]) -> bool {
        match self.known.get(id as usize) {
            Some(b) => *b,
            None => keys_lc
                .get(id as usize)
                .is_some_and(|k| self.names_lc.iter().any(|n| key_matches(n, k))),
        }
    }
}

/// Does a (lowercased) field name typed in a query refer to this (lowercased) field key?
/// Matches the full dotted path or its last segment, ignoring spaces, so `NewValue` finds
/// Defender's `New Value`.
pub fn key_matches(name_lc: &str, key_lc: &str) -> bool {
    let last = key_lc.rsplit('.').next().unwrap_or(key_lc);
    eq_ignoring_spaces(key_lc, name_lc) || eq_ignoring_spaces(last, name_lc)
}

fn eq_ignoring_spaces(a: &str, b: &str) -> bool {
    a.bytes()
        .filter(|&c| c != b' ')
        .eq(b.bytes().filter(|&c| c != b' '))
}

/// Short names for common fields. `process`/`parentprocess` cover both Sysmon (`Image`,
/// `ParentImage`) and Security 4688 (`NewProcessName`, `ParentProcessName`) naming.
fn alias(name: &str) -> Vec<String> {
    let names: &[&str] = match name {
        "id" | "eventid" => &["eventid"],
        "provider" | "source" => &["provider.name"],
        "user" | "usersid" => &["security.userid"],
        "pid" => &["processid"],
        "tid" => &["threadid"],
        "time" => &["timecreated.systemtime"],
        "recordid" | "record" => &["eventrecordid"],
        "process" => &["image", "newprocessname"],
        "parentprocess" => &["parentimage", "parentprocessname"],
        other => return vec![other.to_string()],
    };
    names.iter().map(|n| n.to_string()).collect()
}

struct RawToken {
    negate: bool,
    field: Option<(String, char)>,
    value: String,
}

fn tokenize(q: &str) -> Vec<RawToken> {
    let chars: Vec<char> = q.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        let mut negate = false;
        if chars[i] == '-' && chars.get(i + 1).is_some_and(|c| !c.is_whitespace()) {
            negate = true;
            i += 1;
        }
        let mut buf = String::new();
        let mut field = None;
        let mut in_quotes = false;
        let mut quoted = false;
        while i < chars.len() && (in_quotes || !chars[i].is_whitespace()) {
            let c = chars[i];
            if c == '"' {
                if in_quotes && chars.get(i + 1) == Some(&'"') {
                    buf.push('"');
                    i += 1;
                } else {
                    in_quotes = !in_quotes;
                    quoted = true;
                }
            } else if !in_quotes
                && !quoted
                && field.is_none()
                && matches!(c, ':' | '=' | '~')
                && !buf.is_empty()
                && buf
                    .chars()
                    .all(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '[' | ']'))
            {
                field = Some((std::mem::take(&mut buf), c));
            } else {
                buf.push(c);
            }
            i += 1;
        }
        if buf.is_empty() && field.is_none() {
            continue;
        }
        out.push(RawToken {
            negate,
            field,
            value: buf,
        });
    }
    out
}

impl Query {
    pub fn compile(q: &str, opts: SearchOptions, keys_lc: &[Box<str>]) -> Result<Self, String> {
        Self::compile_with(q, opts, keys_lc, false)
    }

    /// With `strict`, `Field:value` terms always mean a field, even if no record has that
    /// field (they then simply never match). Detection rules use this so a condition can't
    /// silently turn into a plain-text search on logs that lack the field.
    pub fn compile_with(
        q: &str,
        opts: SearchOptions,
        keys_lc: &[Box<str>],
        strict: bool,
    ) -> Result<Self, String> {
        let q = q.trim();
        if q.is_empty() {
            return Ok(Query::Empty);
        }
        let ci = !opts.case_sensitive;
        let build_regex = |pat: &str| {
            RegexBuilder::new(pat)
                .case_insensitive(ci)
                .multi_line(true)
                .size_limit(50 << 20)
                .build()
                .map_err(|e| e.to_string())
        };
        if opts.regex {
            return build_regex(q).map(Query::Regex);
        }

        let fold = |s: &str| if ci { s.to_lowercase() } else { s.to_string() };
        let mut terms = Vec::new();
        for t in tokenize(q) {
            let kind = match t.field {
                Some((name, op)) => {
                    let key = KeyMatch::new(&name, keys_lc);
                    if strict || key.any_known() {
                        let op = match op {
                            ':' => Op::Contains(fold(&t.value)),
                            '=' => Op::Equals(fold(&t.value)),
                            _ => Op::Regex(
                                build_regex(&t.value).map_err(|e| format!("{name}~: {e}"))?,
                            ),
                        };
                        Kind::Field { key, op }
                    } else {
                        // Not a known field (e.g. `C:\Windows`), so search it as plain text.
                        text_kind(fold(&format!("{name}{op}{}", t.value)))
                    }
                }
                None => text_kind(fold(&t.value)),
            };
            terms.push(Term {
                negate: t.negate,
                kind,
            });
        }
        Ok(Query::Terms(terms))
    }

    pub fn matches(&self, r: &Record, opts: SearchOptions, keys_lc: &[Box<str>]) -> bool {
        match self {
            Query::Empty => true,
            Query::Regex(re) => re.is_match(&r.text),
            Query::Terms(terms) => terms
                .iter()
                .all(|t| t.matches(r, opts, keys_lc) != t.negate),
        }
    }

    /// Byte ranges in `value` to highlight, for a field shown in the details pane.
    pub fn highlights(
        &self,
        key_id: u32,
        keys_lc: &[Box<str>],
        key: &str,
        value: &str,
        opts: SearchOptions,
    ) -> Vec<Range<usize>> {
        let mut out = Vec::new();
        match self {
            Query::Empty => {}
            Query::Regex(re) => {
                // Regexes run over `Field=value` lines, so match the same shape and map
                // the hits back onto the value.
                let line = format!("{key}={value}");
                let offset = key.len() + 1;
                for m in re.find_iter(&line) {
                    let (s, e) = (m.start().max(offset), m.end());
                    if e > s {
                        out.push(s - offset..e - offset);
                    }
                }
            }
            Query::Terms(terms) => {
                for t in terms.iter().filter(|t| !t.negate) {
                    match &t.kind {
                        Kind::Text { needle, .. } => find_all(value, needle, opts, &mut out),
                        Kind::Field { key, op } if key.matches(key_id, keys_lc) => match op {
                            Op::Contains(n) => find_all(value, n, opts, &mut out),
                            Op::Equals(_) => out.push(0..value.len()),
                            Op::Regex(re) => out.extend(re.find_iter(value).map(|m| m.range())),
                        },
                        Kind::Field { .. } => {}
                    }
                }
            }
        }
        out.retain(|r| !r.is_empty());
        out.sort_by_key(|r| r.start);
        out
    }

    /// True if every record matching `new` is guaranteed to also match `old`, so the new
    /// query only needs to be run over the old query's hits (e.g. while typing more letters).
    pub fn narrows(old: &str, new: &str, opts: SearchOptions) -> bool {
        if opts.regex || !new.trim_start().starts_with(old.trim()) || old.trim().is_empty() {
            return false;
        }
        // Negations, exact/regex field terms and aliased field names (whose typed name
        // needn't appear in the record text) can all widen the result set.
        let safe = |q: &str| {
            tokenize(q).iter().all(|t| {
                !t.negate
                    && match &t.field {
                        None => true,
                        Some((name, op)) => {
                            *op == ':' && alias(&name.to_lowercase()) == [name.to_lowercase()]
                        }
                    }
            })
        };
        safe(old) && safe(new)
    }
}

fn text_kind(needle: String) -> Kind {
    let finder = Finder::new(needle.as_bytes()).into_owned();
    Kind::Text { needle, finder }
}

impl Term {
    #[inline]
    fn matches(&self, r: &Record, opts: SearchOptions, keys_lc: &[Box<str>]) -> bool {
        let ci = !opts.case_sensitive;
        match &self.kind {
            Kind::Text { finder, .. } => {
                let hay = if ci { &r.text_lc } else { &r.text };
                finder.find(hay.as_bytes()).is_some()
            }
            Kind::Field { key, op } => {
                r.fields
                    .iter()
                    .filter(|f| key.matches(f.key, keys_lc))
                    .any(|f| {
                        let note = r.note(f).unwrap_or("");
                        match op {
                            Op::Contains(n) if ci => {
                                r.value_lc(f).contains(n.as_str())
                                    || note.to_lowercase().contains(n.as_str())
                            }
                            Op::Contains(n) => {
                                r.value(f).contains(n.as_str()) || note.contains(n.as_str())
                            }
                            Op::Equals(v) if ci => {
                                *r.value_lc(f) == **v || note.to_lowercase() == *v
                            }
                            Op::Equals(v) => r.value(f) == v || note == v,
                            Op::Regex(re) => {
                                re.is_match(r.value(f)) || (!note.is_empty() && re.is_match(note))
                            }
                        }
                    })
            }
        }
    }
}

fn find_all(value: &str, needle: &str, opts: SearchOptions, out: &mut Vec<Range<usize>>) {
    if needle.is_empty() {
        return;
    }
    // ASCII lowercasing keeps byte offsets stable, which is what highlighting needs.
    let hay = if opts.case_sensitive {
        value.to_string()
    } else {
        value.to_ascii_lowercase()
    };
    let needle = if opts.case_sensitive {
        needle.to_string()
    } else {
        needle.to_ascii_lowercase()
    };
    let mut start = 0;
    while let Some(pos) = hay[start..].find(&needle) {
        out.push(start + pos..start + pos + needle.len());
        start += pos + needle.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::KeyInterner;

    fn record(event_data: serde_json::Value, keys: &mut KeyInterner) -> Record {
        let json = serde_json::json!({"Event": {
            "System": {"Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                       "EventID": 4625, "Level": 0, "Computer": "DC01",
                       "Execution": {"#attributes": {"ProcessID": 612}}},
            "EventData": event_data,
        }});
        crate::model::build(1, json, keys)
    }

    fn setup() -> (Record, Vec<Box<str>>) {
        let mut keys = KeyInterner::default();
        let r = record(
            serde_json::json!({"TargetUserName": "Administrator", "LogonType": 3,
                               "SubStatus": "0xc000006a", "IpAddress": "10.0.0.5",
                               "ProcessName": "C:\\Windows\\System32\\svchost.exe"}),
            &mut keys,
        );
        let keys_lc = keys
            .take_new()
            .iter()
            .map(|k| k.to_lowercase().into())
            .collect();
        (r, keys_lc)
    }

    fn check(q: &str, opts: SearchOptions) -> bool {
        let (r, keys) = setup();
        Query::compile(q, opts, &keys)
            .unwrap()
            .matches(&r, opts, &keys)
    }

    const CI: SearchOptions = SearchOptions {
        regex: false,
        case_sensitive: false,
    };
    const CS: SearchOptions = SearchOptions {
        regex: false,
        case_sensitive: true,
    };
    const RE: SearchOptions = SearchOptions {
        regex: true,
        case_sensitive: false,
    };

    #[test]
    fn text_terms() {
        assert!(check("admin", CI));
        assert!(!check("admin", CS));
        assert!(check("Admin 10.0.0", CI));
        assert!(!check("admin nothere", CI));
        assert!(check("-nothere", CI));
        assert!(!check("-admin", CI));
        assert!(
            check("\"failed to log on\"", CI),
            "description is searchable"
        );
        assert!(
            check("c:\\windows\\system32", CI),
            "unknown key falls back to text"
        );
    }

    #[test]
    fn field_terms() {
        assert!(check("TargetUserName:admin", CI));
        assert!(!check("IpAddress:admin", CI));
        assert!(check("LogonType=3", CI));
        assert!(check("logontype=network", CI), "decoded note matches");
        assert!(!check("LogonType=31", CI));
        assert!(check("-LogonType=2", CI));
        assert!(check("SubStatus:\"wrong password\"", CI));
        assert!(check("pid=612", CI), "alias + last-segment match");
        assert!(check("Computer=dc01", CI));
        assert!(check("IpAddress~^10\\.0\\.0\\.\\d+$", CI));
        assert!(check("TargetUserName:", CI), "field exists");
        assert!(!check("CommandLine:", CI));
        assert!(key_matches("newvalue", "new value"));
        assert!(key_matches("new value", "eventdata.new value"));
        assert!(!key_matches("newvalue", "old value"));
    }

    #[test]
    fn regex_mode() {
        assert!(check("^TargetUserName=admin", RE));
        assert!(check("svchost\\.exe$", RE));
        assert!(!check("^LogonType=2$", RE));
        assert!(Query::compile("(unclosed", RE, &[]).is_err());
    }

    #[test]
    fn narrowing() {
        assert!(Query::narrows("adm", "admin", CI));
        assert!(Query::narrows("admin", "admin 10.0", CI));
        assert!(Query::narrows("TargetUser", "TargetUserName:x", CI));
        assert!(!Query::narrows("admin", "admin -x", CI));
        assert!(!Query::narrows("LogonType=3", "LogonType=31", CI));
        assert!(!Query::narrows("adm", "admin", RE));
        assert!(!Query::narrows("-", "-foo", CI));
        assert!(!Query::narrows("pid", "pid:612", CI));
    }

    #[test]
    fn highlighting() {
        let (_, keys) = setup();
        let q = Query::compile("admin", CI, &keys).unwrap();
        assert_eq!(
            q.highlights(0, &keys, "TargetUserName", "Administrator", CI),
            vec![0..5]
        );
        let q = Query::compile("^TargetUserName=admin", RE, &keys).unwrap();
        assert_eq!(
            q.highlights(0, &keys, "TargetUserName", "Administrator", RE),
            vec![0..5]
        );
    }
}

#[cfg(test)]
mod sample_tests {
    use super::*;
    use crate::model::{Draft, KeyInterner, Record};

    /// `EVTX_SAMPLE=file EVTX_QUERY='q1;;q2' cargo test sample_queries -- --nocapture`
    #[test]
    fn sample_queries() {
        let (Ok(path), Ok(queries)) = (std::env::var("EVTX_SAMPLE"), std::env::var("EVTX_QUERY"))
        else {
            return;
        };
        let mut parser = evtx::EvtxParser::from_path(path).unwrap();
        let mut keys = KeyInterner::default();
        let records: Vec<Record> = parser
            .records_json_value()
            .filter_map(Result::ok)
            .map(|r| {
                Draft::new(r.event_record_id, 0, r.timestamp.to_string(), r.data).finish(&mut keys)
            })
            .collect();
        let keys_lc: Vec<Box<str>> = keys
            .take_new()
            .iter()
            .map(|k| k.to_lowercase().into())
            .collect();
        for q in queries.split(";;") {
            let (q, opts) = match q.strip_prefix("re:") {
                Some(r) => (
                    r,
                    SearchOptions {
                        regex: true,
                        case_sensitive: false,
                    },
                ),
                None => (q, SearchOptions::default()),
            };
            let query = Query::compile(q, opts, &keys_lc).unwrap();
            let t = std::time::Instant::now();
            let hits: Vec<&Record> = records
                .iter()
                .filter(|r| query.matches(r, opts, &keys_lc))
                .collect();
            println!(
                "{q:40} -> {:5} hits in {:?}  ids: {:?}",
                hits.len(),
                t.elapsed(),
                hits.iter()
                    .map(|r| r.event_id)
                    .collect::<std::collections::BTreeSet<_>>()
            );
        }
    }
}

#[cfg(test)]
mod bench {
    use super::*;
    use crate::model::{Draft, KeyInterner};
    use rayon::prelude::*;
    use std::time::Instant;

    /// Scale test: `EVTX_SAMPLE=file cargo test --release bench_scale -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn bench_scale() {
        let Ok(path) = std::env::var("EVTX_SAMPLE") else {
            return;
        };
        let target: usize = std::env::var("EVTX_N")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(500_000);
        let mut parser = evtx::EvtxParser::from_path(&path).unwrap();
        let raw: Vec<_> = parser.records_json_value().filter_map(Result::ok).collect();
        let mut keys = KeyInterner::default();
        let t = Instant::now();
        let mut records = Vec::with_capacity(target);
        let mut id = 0u64;
        while records.len() < target {
            for r in &raw {
                id += 1;
                records.push(
                    Draft::new(id, 0, r.timestamp.to_string(), r.data.clone()).finish(&mut keys),
                );
                if records.len() == target {
                    break;
                }
            }
        }
        println!("built {} records in {:?}", records.len(), t.elapsed());
        let keys_lc: Vec<Box<str>> = keys
            .take_new()
            .iter()
            .map(|k| k.to_lowercase().into())
            .collect();
        let text_bytes: usize = records.iter().map(|r| r.text.len()).sum();
        println!("search text: {} MB", text_bytes >> 20);

        for (q, opts) in [
            ("admin", SearchOptions::default()),
            ("kerberos 0x17", SearchOptions::default()),
            ("TargetUserName:admin", SearchOptions::default()),
            ("LogonType=3 -svchost", SearchOptions::default()),
            (
                "Administrator",
                SearchOptions {
                    regex: false,
                    case_sensitive: true,
                },
            ),
            (
                r"^ServiceName=.*\$$",
                SearchOptions {
                    regex: true,
                    case_sensitive: false,
                },
            ),
            (
                r"(iex|downloadstring|frombase64string)",
                SearchOptions {
                    regex: true,
                    case_sensitive: false,
                },
            ),
        ] {
            let query = Query::compile(q, opts, &keys_lc).unwrap();
            let t = Instant::now();
            let hits: Vec<bool> = records
                .par_iter()
                .map(|r| query.matches(r, opts, &keys_lc))
                .collect();
            let n = hits.iter().filter(|h| **h).count();
            println!(
                "{q:45} {n:8} hits  {:>8.1} ms",
                t.elapsed().as_secs_f64() * 1000.0
            );
        }
        let t = Instant::now();
        let mut order: Vec<u32> = (0..records.len() as u32).collect();
        order.par_sort_unstable_by(|&a, &b| {
            records[a as usize]
                .timestamp
                .cmp(&records[b as usize].timestamp)
        });
        println!("sort by time: {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
    }
}
