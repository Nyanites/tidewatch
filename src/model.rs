use std::collections::HashMap;

use serde_json::Value;

use crate::known;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Section {
    System,
    EventData,
    UserData,
    /// Anything else under <Event>, e.g. RenderingInfo or ProcessingErrorData.
    Other,
}

/// One element of an event. Its value (and decoded note, if any) are byte ranges into the
/// owning record's `text`, so a field costs no allocations of its own.
pub struct Field {
    /// Interned key, see [`KeyInterner`].
    pub key: u32,
    pub section: Section,
    start: u32,
    len: u32,
    note_start: u32,
    note_len: u32,
}

/// Indexes into `Record::cols`.
#[derive(Clone, Copy)]
pub enum Col {
    Provider,
    Channel,
    Computer,
    UserSid,
    Pid,
    Tid,
    Task,
    Opcode,
    Keywords,
    EventRecordId,
}

const COL_KEYS: [&str; 10] = [
    "Provider.Name",
    "Channel",
    "Computer",
    "Security.UserID",
    "Execution.ProcessID",
    "Execution.ThreadID",
    "Task",
    "Opcode",
    "Keywords",
    "EventRecordID",
];
const NO_FIELD: u16 = u16::MAX;

/// One parsed event. Everything in the event is kept in `fields`; the table columns are
/// indexes into them.
pub struct Record {
    pub record_id: u64,
    /// Chunk the record lives in, used to re-render its JSON/XML on demand.
    pub chunk: u32,
    pub timestamp: Box<str>,
    pub level: u8,
    pub event_id: u32,
    pub description: &'static str,
    cols: [u16; 10],
    pub fields: Box<[Field]>,
    /// `Field=value (note)` lines for every field: what search runs on and where field
    /// values live.
    pub text: Box<str>,
    /// Lowercased `text`, for fast case-insensitive search.
    pub text_lc: Box<str>,
}

impl Record {
    pub fn value(&self, f: &Field) -> &str {
        &self.text[f.start as usize..(f.start + f.len) as usize]
    }

    /// Lowercased value. Borrowed from `text_lc` when lowercasing kept byte offsets intact.
    pub fn value_lc(&self, f: &Field) -> std::borrow::Cow<'_, str> {
        let range = f.start as usize..(f.start + f.len) as usize;
        match self.text_lc.get(range) {
            Some(s) if self.text_lc.len() == self.text.len() => s.into(),
            _ => self.value(f).to_lowercase().into(),
        }
    }

    pub fn note(&self, f: &Field) -> Option<&str> {
        (f.note_len > 0)
            .then(|| &self.text[f.note_start as usize..(f.note_start + f.note_len) as usize])
    }

    pub fn col(&self, c: Col) -> &str {
        match self.cols[c as usize] {
            NO_FIELD => "",
            i => self.value(&self.fields[i as usize]),
        }
    }

    pub fn provider(&self) -> &str {
        self.col(Col::Provider)
    }

    /// Compact one-line summary of EventData/UserData, built on demand for visible rows.
    pub fn summary(&self, keys: &[Box<str>], max: usize) -> String {
        let mut s = String::new();
        for f in self
            .fields
            .iter()
            .filter(|f| matches!(f.section, Section::EventData | Section::UserData))
        {
            let v = self.value(f);
            if v.is_empty() || v == "-" {
                continue;
            }
            if !s.is_empty() {
                s.push_str("  ");
            }
            let k = &*keys[f.key as usize];
            s.push_str(k.rsplit('.').next().unwrap_or(k));
            s.push('=');
            s.extend(v.chars().map(|c| if c.is_control() { ' ' } else { c }));
            if s.len() > max {
                let mut cut = max;
                while !s.is_char_boundary(cut) {
                    cut -= 1;
                }
                s.truncate(cut);
                s.push('…');
                break;
            }
        }
        s
    }
}

/// A record built off the UI thread, before its field names are interned.
pub struct Draft {
    record_id: u64,
    chunk: u32,
    timestamp: String,
    level: u8,
    event_id: u32,
    description: &'static str,
    cols: [u16; 10],
    fields: Vec<(String, Field)>,
    text: String,
}

impl Draft {
    pub fn new(record_id: u64, chunk: u32, fallback_ts: String, json: Value) -> Self {
        let mut flat: Vec<(Section, String, String)> = Vec::new();
        if let Some(event) = json["Event"].as_object() {
            for (name, child) in event {
                let mut out = Vec::new();
                let section = match name.as_str() {
                    "#attributes" => continue,
                    "System" => Section::System,
                    "EventData" => Section::EventData,
                    "UserData" => Section::UserData,
                    _ => Section::Other,
                };
                flatten(
                    child,
                    if section == Section::Other { name } else { "" },
                    &mut out,
                );
                flat.extend(out.into_iter().map(|(k, v)| {
                    let k = if k.is_empty() { "Data".to_string() } else { k };
                    (section, k, v)
                }));
            }
        }

        let system = |key: &str| -> &str {
            flat.iter()
                .find(|(s, k, _)| *s == Section::System && k == key)
                .map(|(_, _, v)| v.as_str())
                .unwrap_or("")
        };
        let timestamp = match system("TimeCreated.SystemTime") {
            "" => fallback_ts.replacen('T', " ", 1),
            ts => ts.replacen('T', " ", 1),
        };
        let level: u8 = system("Level").parse().unwrap_or(0);
        let event_id: u32 = system("EventID").parse().unwrap_or(0);
        let description = known::describe(system("Provider.Name"), event_id);

        let mut cols = [NO_FIELD; 10];
        let mut text = String::with_capacity(
            flat.iter()
                .map(|(_, k, v)| k.len() + v.len() + 2)
                .sum::<usize>()
                + 64,
        );
        if !description.is_empty() {
            text.push_str("Description=");
            text.push_str(description);
            text.push('\n');
        }
        let mut fields = Vec::with_capacity(flat.len());
        for (section, k, v) in flat {
            // Bound what one (possibly malicious) record can make us store; also keeps the
            // u32 offsets below valid.
            if fields.len() >= MAX_FIELDS_PER_RECORD || text.len() >= MAX_RECORD_TEXT {
                break;
            }
            let v = truncate_value(v);
            if section == Section::System && fields.len() < NO_FIELD as usize {
                if let Some(c) = COL_KEYS.iter().position(|ck| *ck == k) {
                    cols[c] = fields.len() as u16;
                }
            }
            text.push_str(&k);
            text.push('=');
            let start = text.len() as u32;
            text.push_str(&v);
            let len = v.len() as u32;
            let (mut note_start, mut note_len) = (0, 0);
            if let Some(n) = known::annotate(k.rsplit('.').next().unwrap_or(&k), &v) {
                text.push_str(" (");
                note_start = text.len() as u32;
                note_len = n.len() as u32;
                text.push_str(&n);
                text.push(')');
            }
            text.push('\n');
            fields.push((
                k,
                Field {
                    key: 0,
                    section,
                    start,
                    len,
                    note_start,
                    note_len,
                },
            ));
        }

        Self {
            record_id,
            chunk,
            timestamp,
            level,
            event_id,
            description,
            cols,
            fields,
            text,
        }
    }

    pub fn finish(self, keys: &mut KeyInterner) -> Record {
        let fields = self
            .fields
            .into_iter()
            .map(|(k, mut f)| {
                f.key = keys.intern(&k);
                f
            })
            .collect();
        Record {
            record_id: self.record_id,
            chunk: self.chunk,
            timestamp: self.timestamp.into(),
            level: self.level,
            event_id: self.event_id,
            description: self.description,
            cols: self.cols,
            fields,
            text_lc: self.text.to_lowercase().into(),
            text: self.text.into(),
        }
    }
}

/// Field names are shared by thousands of records, so they're stored once and referenced by id.
/// Ids are assigned in order, so a receiver can mirror the table by appending new names.
#[derive(Default)]
pub struct KeyInterner {
    names: Vec<Box<str>>,
    lookup: HashMap<Box<str>, u32>,
    sent: usize,
}

impl KeyInterner {
    pub fn intern(&mut self, key: &str) -> u32 {
        if let Some(&id) = self.lookup.get(key) {
            return id;
        }
        // Cap distinct field names per file; everything past the cap shares one name.
        if self.names.len() >= MAX_DISTINCT_KEYS {
            return self.intern_overflow();
        }
        let id = self.names.len() as u32;
        self.names.push(key.into());
        self.lookup.insert(key.into(), id);
        id
    }

    fn intern_overflow(&mut self) -> u32 {
        const OVERFLOW: &str = "(other fields)";
        if let Some(&id) = self.lookup.get(OVERFLOW) {
            return id;
        }
        let id = self.names.len() as u32;
        self.names.push(OVERFLOW.into());
        self.lookup.insert(OVERFLOW.into(), id);
        id
    }

    /// Names interned since the last call.
    pub fn take_new(&mut self) -> Vec<Box<str>> {
        let new = self.names[self.sent..].to_vec();
        self.sent = self.names.len();
        new
    }
}

pub fn level_name(level: u8) -> &'static str {
    match level {
        0 => "Information",
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        4 => "Information",
        5 => "Verbose",
        _ => "Unknown",
    }
}

const MAX_FIELDS_PER_RECORD: usize = 10_000;
const MAX_DISTINCT_KEYS: usize = 50_000;
const MAX_RECORD_TEXT: usize = 32 << 20;
const MAX_VALUE_BYTES: usize = 1 << 20;
/// Nesting deeper than this is replaced by a placeholder (bounds recursion).
const MAX_FLATTEN_DEPTH: usize = 48;
/// Array elements past this index share one field name, so a huge array can't create
/// thousands of distinct field names.
const MAX_INDEXED_ELEMENTS: usize = 64;

fn truncate_value(mut v: String) -> String {
    if v.len() > MAX_VALUE_BYTES {
        let mut cut = MAX_VALUE_BYTES;
        while !v.is_char_boundary(cut) {
            cut -= 1;
        }
        v.truncate(cut);
        v.push_str(" …[truncated by Tidewatch]");
    }
    v
}

/// Flatten a JSON tree into dotted `key = value` pairs, folding `#attributes`/`#text`
/// into their parent key.
fn flatten(v: &Value, prefix: &str, out: &mut Vec<(String, String)>) {
    flatten_at(v, prefix, out, 0);
}

fn flatten_at(v: &Value, prefix: &str, out: &mut Vec<(String, String)>, depth: usize) {
    if depth >= MAX_FLATTEN_DEPTH && (v.is_object() || v.is_array()) {
        out.push((
            prefix.to_string(),
            "[nested too deeply to display]".to_string(),
        ));
        return;
    }
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                let key = if k == "#attributes" || k == "#text" {
                    prefix.to_string()
                } else if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten_at(child, &key, out, depth + 1);
            }
        }
        Value::Array(arr) => {
            for (i, child) in arr.iter().enumerate() {
                let key = if i < MAX_INDEXED_ELEMENTS {
                    format!("{prefix}[{i}]")
                } else {
                    format!("{prefix}[*]")
                };
                flatten_at(child, &key, out, depth + 1);
            }
        }
        Value::Null => out.push((prefix.to_string(), String::new())),
        Value::String(s) => out.push((prefix.to_string(), s.clone())),
        other => out.push((prefix.to_string(), other.to_string())),
    }
}

#[cfg(test)]
pub fn build(record_id: u64, json: Value, keys: &mut KeyInterner) -> Record {
    Draft::new(record_id, 0, String::new(), json).finish(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Value {
        serde_json::json!({"Event": {
            "#attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"},
            "System": {
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing", "Guid": "{5484}"}},
                "EventID": 4624, "Version": 2, "Level": 0, "Task": 12544, "Opcode": 0,
                "Keywords": "0x8020000000000000",
                "TimeCreated": {"#attributes": {"SystemTime": "2016-07-08T18:12:51.681640Z"}},
                "EventRecordID": 2,
                "Execution": {"#attributes": {"ProcessID": 456, "ThreadID": 460}},
                "Channel": "Security", "Computer": "WIN-HOST",
                "Security": {"#attributes": {"UserID": "S-1-5-18"}}
            },
            "EventData": {"TargetUserName": "SYSTEM", "LogonType": 5},
            "RenderingInfo": {"Message": "An account was successfully logged on."}
        }})
    }

    #[test]
    fn extracts_everything() {
        let mut keys = KeyInterner::default();
        let r = build(2, sample(), &mut keys);
        assert_eq!(&*r.timestamp, "2016-07-08 18:12:51.681640Z");
        assert_eq!((r.event_id, r.level), (4624, 0));
        assert_eq!(r.col(Col::Computer), "WIN-HOST");
        assert_eq!(r.col(Col::UserSid), "S-1-5-18");
        assert_eq!((r.col(Col::Pid), r.col(Col::Tid)), ("456", "460"));
        assert_eq!(r.provider(), "Microsoft-Windows-Security-Auditing");
        assert_eq!(r.description, "An account was successfully logged on");
        assert!(r.text.contains("LogonType=5 (Service)\n"));
        assert!(r
            .text
            .contains("Keywords=0x8020000000000000 (Audit Success)\n"));
        assert!(r.text.contains("RenderingInfo.Message=An account"));
        let names = keys.take_new();
        assert!(names.iter().any(|n| &**n == "Provider.Guid"));
        let logon = r
            .fields
            .iter()
            .find(|f| &*names[f.key as usize] == "LogonType")
            .unwrap();
        assert_eq!((r.value(logon), r.note(logon)), ("5", Some("Service")));
        assert!(r.fields.iter().any(|f| f.section == Section::Other));
        assert_eq!(r.summary(&names, 300), "TargetUserName=SYSTEM  LogonType=5");
    }

    #[test]
    fn non_ascii_lowercase() {
        let mut keys = KeyInterner::default();
        let json = serde_json::json!({"Event": {"System": {"EventID": 1}, "EventData": {"Name": "İSTANBUL"}}});
        let r = build(1, json, &mut keys);
        let f = r
            .fields
            .iter()
            .find(|f| f.section == Section::EventData)
            .unwrap();
        assert_eq!(r.value(f), "İSTANBUL");
        assert_eq!(r.value_lc(f), "i̇stanbul");
    }

    #[test]
    fn hostile_records_are_bounded() {
        // Deep nesting (would overflow the stack if flattened recursively without a cap).
        // Built, flattened and dropped on a big-stack thread: serde_json itself recurses.
        let handle = std::thread::Builder::new()
            .stack_size(64 << 20)
            .spawn(|| {
                let mut v = Value::String("leaf".into());
                for _ in 0..1_500 {
                    let mut m = serde_json::Map::new();
                    m.insert("a".into(), v);
                    v = Value::Object(m);
                }
                let mut data = serde_json::Map::new();
                data.insert("Deep".into(), v);
                let mut event = serde_json::Map::new();
                event.insert("System".into(), serde_json::json!({"EventID": 1}));
                event.insert("EventData".into(), Value::Object(data));
                let mut root = serde_json::Map::new();
                root.insert("Event".into(), Value::Object(event));
                let mut keys = KeyInterner::default();
                build(1, Value::Object(root), &mut keys).fields.len()
            })
            .unwrap();
        assert!(handle.join().unwrap() >= 1);

        // Huge value and huge array.
        let mut keys = KeyInterner::default();
        let big = "é".repeat(MAX_VALUE_BYTES);
        let arr: Vec<u32> = (0..5000).collect();
        let json = serde_json::json!({"Event": {"System": {"EventID": 1}, "EventData": {"Big": big, "Arr": arr}}});
        let r = build(1, json, &mut keys);
        let bigf = r
            .fields
            .iter()
            .find(|f| r.value(f).contains("truncated"))
            .unwrap();
        assert!(r.value(bigf).len() <= MAX_VALUE_BYTES + 64);
        assert!(
            keys.take_new().len() < MAX_INDEXED_ELEMENTS + 10,
            "array indices collapse"
        );
    }
}
