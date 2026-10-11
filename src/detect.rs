//! Built-in hunting rules ("Detections") and the engine that runs them over a loaded log.
//!
//! A rule is data: which provider/event IDs it applies to, one or more conditions in the
//! app's own query language (any one may match), and optionally a threshold — "N events
//! (or N distinct values of a field) for the same group within a time window" — for
//! patterns such as password spraying. Rules live in [`crate::rules`].

use std::collections::HashMap;

use rayon::prelude::*;

use crate::model::Record;
use crate::search::{Query, SearchOptions};

// Not every level/tactic is used yet: the rule library is being filled in tactic by tactic.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }
}

/// MITRE ATT&CK tactics, in kill-chain order (used to group rules in the menu).
/// MITRE ATT&CK tactics, in kill-chain order (used to group rules in the menu).
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Tactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
    Other,
}

impl Tactic {
    pub fn label(self) -> &'static str {
        match self {
            Tactic::Reconnaissance => "Reconnaissance",
            Tactic::ResourceDevelopment => "Resource Development",
            Tactic::InitialAccess => "Initial Access",
            Tactic::Execution => "Execution",
            Tactic::Persistence => "Persistence",
            Tactic::PrivilegeEscalation => "Privilege Escalation",
            Tactic::DefenseEvasion => "Defense Evasion",
            Tactic::CredentialAccess => "Credential Access",
            Tactic::Discovery => "Discovery",
            Tactic::LateralMovement => "Lateral Movement",
            Tactic::Collection => "Collection",
            Tactic::CommandAndControl => "Command and Control",
            Tactic::Exfiltration => "Exfiltration",
            Tactic::Impact => "Impact",
            Tactic::Other => "Other",
        }
    }

    /// From a Sigma tag such as `attack.credential-access`.
    fn from_tag(tag: &str) -> Option<Self> {
        Some(match tag.strip_prefix("attack.")? {
            "reconnaissance" => Tactic::Reconnaissance,
            "resource-development" | "resource_development" => Tactic::ResourceDevelopment,
            "initial-access" | "initial_access" => Tactic::InitialAccess,
            "execution" => Tactic::Execution,
            "persistence" => Tactic::Persistence,
            "privilege-escalation" | "privilege_escalation" => Tactic::PrivilegeEscalation,
            "defense-evasion" | "defense_evasion" | "defense-impairment" => Tactic::DefenseEvasion,
            "credential-access" | "credential_access" => Tactic::CredentialAccess,
            "discovery" => Tactic::Discovery,
            "lateral-movement" | "lateral_movement" => Tactic::LateralMovement,
            "collection" => Tactic::Collection,
            "command-and-control" | "command_and_control" => Tactic::CommandAndControl,
            "exfiltration" => Tactic::Exfiltration,
            "impact" => Tactic::Impact,
            _ => return None,
        })
    }
}

/// "At least `min` matching events — or `min` distinct values of `distinct` — sharing the
/// same `group_by` values within `window_secs`."
pub struct Threshold {
    pub group_by: &'static [&'static str],
    pub distinct: Option<&'static str>,
    pub min: usize,
    pub window_secs: i64,
}

/// Licence of the rule sources (Sigma, Hayabusa) the built-in rules are adapted from.
pub const RULE_LICENSE_URL: &str = "https://github.com/SigmaHQ/Detection-Rule-License";

pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    /// Authors of the original rule(s) this one is adapted from. The Detection Rule License
    /// requires showing this wherever matches are displayed.
    pub author: &'static str,
    pub tactic: Tactic,
    /// ATT&CK technique ID(s), e.g. "T1558.003".
    pub mitre: &'static str,
    pub severity: Severity,
    pub description: &'static str,
    /// Provider names (case-insensitive); empty = any provider.
    pub providers: &'static [&'static str],
    pub event_ids: &'static [u32],
    /// Conditions in the query language; a record matches if ANY of them matches.
    /// Empty = every event with a listed ID matches.
    pub any_of: &'static [&'static str],
    pub threshold: Option<Threshold>,
    pub false_positives: &'static str,
    pub references: &'static [&'static str],
}

/// Where a rule comes from.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RuleSource {
    BuiltIn,
    Sigma,
}

/// A rule ready to run and display: a built-in rule or an imported Sigma rule.
pub struct DetRule {
    pub id: String,
    pub name: String,
    pub author: String,
    pub tactic: Tactic,
    pub mitre: String,
    pub severity: Severity,
    pub description: String,
    /// Where it looks, e.g. "Security 4769" or "Sysmon 1, Security 4688".
    pub log_source: String,
    /// Matching logic as shown to the user.
    pub logic: Vec<String>,
    pub threshold: Option<&'static Threshold>,
    pub false_positives: String,
    pub references: Vec<String>,
    pub source: RuleSource,
    /// File the rule was loaded from (Sigma).
    pub location: String,
    /// Full detection section (Sigma YAML), for display.
    pub detail: String,
    pub license_url: Option<String>,
    /// Sigma `status` (stable, test, experimental); empty for built-ins.
    pub status: String,
    kind: Kind,
}

enum Kind {
    BuiltIn(&'static Rule),
    Sigma(Box<crate::sigma::SigmaRule>),
}

impl DetRule {
    pub fn from_builtin(r: &'static Rule) -> Self {
        let ids: Vec<String> = r.event_ids.iter().map(u32::to_string).collect();
        DetRule {
            id: r.id.to_string(),
            name: r.name.to_string(),
            author: r.author.to_string(),
            tactic: r.tactic,
            mitre: r.mitre.to_string(),
            severity: r.severity,
            description: r.description.to_string(),
            log_source: format!("Events {}", ids.join(", ")),
            logic: if r.any_of.is_empty() {
                vec!["any event with these IDs".into()]
            } else {
                r.any_of.iter().map(|q| q.to_string()).collect()
            },
            threshold: r.threshold.as_ref(),
            false_positives: r.false_positives.to_string(),
            references: r.references.iter().map(|u| u.to_string()).collect(),
            source: RuleSource::BuiltIn,
            location: String::new(),
            detail: String::new(),
            license_url: (!r.author.is_empty()).then(|| RULE_LICENSE_URL.to_string()),
            status: String::new(),
            kind: Kind::BuiltIn(r),
        }
    }

    pub fn from_sigma(r: crate::sigma::SigmaRule, drl: bool) -> Self {
        let tactic = r
            .tags
            .iter()
            .find_map(|t| Tactic::from_tag(&t.to_lowercase()))
            .unwrap_or(Tactic::Other);
        let mitre: Vec<String> = r
            .tags
            .iter()
            .filter_map(|t| t.to_lowercase().strip_prefix("attack.").map(str::to_string))
            .filter(|t| {
                t.starts_with('t') && t[1..].chars().next().is_some_and(|c| c.is_ascii_digit())
            })
            .map(|t| t.to_uppercase())
            .collect();
        let severity = match r.level.as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        };
        let license_url = if !r.license.is_empty() {
            Some(r.license.clone())
        } else {
            drl.then(|| RULE_LICENSE_URL.to_string())
        };
        DetRule {
            id: format!(
                "sigma:{}",
                if r.id.is_empty() {
                    r.path.display().to_string()
                } else {
                    r.id.clone()
                }
            ),
            name: r.title.clone(),
            author: r.author.clone(),
            tactic,
            mitre: mitre.join(", "),
            severity,
            description: r.description.clone(),
            log_source: r.log_source(),
            logic: vec![format!("condition: {}", r.condition_text)],
            threshold: None,
            false_positives: r.falsepositives.join("; "),
            references: r.references.clone(),
            source: RuleSource::Sigma,
            location: r.path.display().to_string(),
            detail: r.detection_yaml.clone(),
            license_url,
            status: r.status.clone(),
            kind: Kind::Sigma(Box::new(r)),
        }
    }
}

/// The built-in library as runnable rules.
pub fn builtin_rules() -> Vec<DetRule> {
    crate::rules::RULES
        .iter()
        .map(DetRule::from_builtin)
        .collect()
}

pub struct Hits {
    pub rule: usize,
    /// Indices into the record list, in record order.
    pub records: Vec<u32>,
}

/// Run every rule. Returns hits for rules that matched at least one record, and errors for
/// rules whose conditions failed to compile.
pub fn run(
    rules: &[DetRule],
    records: &[Record],
    keys_lc: &[Box<str>],
) -> (Vec<Hits>, Vec<String>) {
    // Index records by channel and (channel, event ID) so each Sigma rule only looks at
    // events it could possibly match.
    let channels: Vec<String> = records.par_iter().map(crate::sigma::channel_lc).collect();
    let mut by_channel: HashMap<&str, Vec<u32>> = HashMap::new();
    let mut by_channel_id: HashMap<(&str, u32), Vec<u32>> = HashMap::new();
    for (i, (r, ch)) in records.iter().zip(&channels).enumerate() {
        by_channel.entry(ch.as_str()).or_default().push(i as u32);
        by_channel_id
            .entry((ch.as_str(), r.event_id))
            .or_default()
            .push(i as u32);
    }

    let key_index = crate::sigma::KeyIndex::new(keys_lc);
    let results: Vec<Result<Option<Hits>, String>> = rules
        .par_iter()
        .enumerate()
        .map(|(ri, rule)| {
            let matched = match &rule.kind {
                Kind::BuiltIn(r) => run_builtin(r, records, keys_lc)?,
                Kind::Sigma(sr) => {
                    let compiled = sr.compile(&key_index);
                    let mut candidates: Vec<u32> = Vec::new();
                    for (ch, ids) in sr.targets() {
                        match ids {
                            Some(ids) => {
                                for id in ids {
                                    if let Some(v) = by_channel_id.get(&(ch, id)) {
                                        candidates.extend(v);
                                    }
                                }
                            }
                            None => {
                                if let Some(v) = by_channel.get(ch) {
                                    candidates.extend(v);
                                }
                            }
                        }
                    }
                    candidates.sort_unstable();
                    candidates.dedup();
                    candidates
                        .into_iter()
                        .filter(|&i| compiled.matches(&records[i as usize], &channels[i as usize]))
                        .collect()
                }
            };
            Ok((!matched.is_empty()).then_some(Hits {
                rule: ri,
                records: matched,
            }))
        })
        .collect();

    let mut hits = Vec::new();
    let mut errors = Vec::new();
    for r in results {
        match r {
            Ok(Some(h)) => hits.push(h),
            Ok(None) => {}
            Err(e) => errors.push(e),
        }
    }
    (hits, errors)
}

fn run_builtin(rule: &Rule, records: &[Record], keys_lc: &[Box<str>]) -> Result<Vec<u32>, String> {
    let opts = SearchOptions {
        regex: false,
        case_sensitive: false,
    };
    let queries = rule
        .any_of
        .iter()
        .map(|q| {
            Query::compile_with(q, opts, keys_lc, true).map_err(|e| format!("{}: {e}", rule.id))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let providers: Vec<String> = rule.providers.iter().map(|p| p.to_lowercase()).collect();
    let mut matched: Vec<u32> = records
        .par_iter()
        .enumerate()
        .filter(|(_, r)| {
            rule.event_ids.contains(&r.event_id)
                && (providers.is_empty()
                    || providers
                        .iter()
                        .any(|p| r.provider().eq_ignore_ascii_case(p)))
                && (queries.is_empty() || queries.iter().any(|q| q.matches(r, opts, keys_lc)))
        })
        .map(|(i, _)| i as u32)
        .collect();
    if let Some(t) = &rule.threshold {
        matched = apply_threshold(t, &matched, records, keys_lc);
    }
    Ok(matched)
}

/// Value of the first field whose name matches `name` (full dotted path or last segment,
/// case-insensitive), the same way query field terms resolve names.
pub fn field_value<'a>(r: &'a Record, keys_lc: &[Box<str>], name_lc: &str) -> Option<&'a str> {
    r.fields
        .iter()
        .find(|f| crate::search::key_matches(name_lc, &keys_lc[f.key as usize]))
        .map(|f| r.value(f))
}

fn apply_threshold(
    t: &Threshold,
    matched: &[u32],
    records: &[Record],
    keys_lc: &[Box<str>],
) -> Vec<u32> {
    let group_names: Vec<String> = t.group_by.iter().map(|g| g.to_lowercase()).collect();
    let distinct = t.distinct.map(str::to_lowercase);

    let mut groups: HashMap<Vec<&str>, Vec<(i64, u32)>> = HashMap::new();
    for &i in matched {
        let r = &records[i as usize];
        let key: Vec<&str> = group_names
            .iter()
            .map(|g| field_value(r, keys_lc, g).unwrap_or(""))
            .collect();
        let Some(ts) = parse_timestamp(&r.timestamp) else {
            continue;
        };
        groups.entry(key).or_default().push((ts, i));
    }

    let mut hit = vec![false; records.len()];
    for events in groups.values_mut() {
        events.sort_unstable();
        // Sliding window over time; count events (or distinct values) inside it.
        let mut lo = 0;
        // Events before this index are already marked; keeps the scan linear.
        let mut marked_upto = 0;
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for hi in 0..events.len() {
            let value_of = |idx: usize| -> &str {
                let r = &records[events[idx].1 as usize];
                distinct
                    .as_deref()
                    .and_then(|d| field_value(r, keys_lc, d))
                    .unwrap_or("")
            };
            *counts.entry(value_of(hi)).or_default() += 1;
            while events[hi].0 - events[lo].0 > t.window_secs {
                let v = value_of(lo);
                if let Some(c) = counts.get_mut(v) {
                    *c -= 1;
                    if *c == 0 {
                        counts.remove(v);
                    }
                }
                lo += 1;
            }
            let size = if distinct.is_some() {
                counts.len()
            } else {
                hi - lo + 1
            };
            if size >= t.min {
                for e in &events[lo.max(marked_upto)..=hi] {
                    hit[e.1 as usize] = true;
                }
                marked_upto = hi + 1;
            }
        }
    }
    matched
        .iter()
        .copied()
        .filter(|&i| hit[i as usize])
        .collect()
}

/// "2024-05-21 03:16:32.588340Z" -> seconds since the Unix epoch.
pub fn parse_timestamp(ts: &str) -> Option<i64> {
    let b = ts.as_bytes();
    // Byte-slicing below needs ASCII; timestamps come from untrusted files.
    if b.len() < 19 || !b[..19].is_ascii() {
        return None;
    }
    let num = |s: &str| s.parse::<i64>().ok();
    let (y, m, d) = (num(&ts[0..4])?, num(&ts[5..7])?, num(&ts[8..10])?);
    let (hh, mm, ss) = (num(&ts[11..13])?, num(&ts[14..16])?, num(&ts[17..19])?);
    // Days from civil date (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{build, KeyInterner};

    #[test]
    fn timestamps() {
        assert_eq!(parse_timestamp("1970-01-01 00:00:00Z"), Some(0));
        assert_eq!(
            parse_timestamp("2024-05-21 03:16:32.588340Z"),
            Some(1_716_261_392)
        );
        assert_eq!(parse_timestamp("2000-03-01 00:00:00"), Some(951_868_800));
        assert_eq!(parse_timestamp("garbage"), None);
        assert_eq!(
            parse_timestamp("2024-05-21 03:1é:32.5Z"),
            None,
            "non-ASCII must not panic"
        );
    }

    fn failed_logon(id: u64, time: &str, ip: &str, user: &str, keys: &mut KeyInterner) -> Record {
        let json = serde_json::json!({"Event": {
            "System": {"Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                       "EventID": 4625, "Level": 0,
                       "TimeCreated": {"#attributes": {"SystemTime": time}}},
            "EventData": {"TargetUserName": user, "IpAddress": ip, "Status": "0xc000006d"},
        }});
        build(id, json, keys)
    }

    const SPRAY: Rule = Rule {
        id: "test_spray",
        name: "spray",
        author: "",
        tactic: Tactic::CredentialAccess,
        mitre: "T1110.003",
        severity: Severity::Medium,
        description: "",
        providers: &["Microsoft-Windows-Security-Auditing"],
        event_ids: &[4625],
        any_of: &[],
        threshold: Some(Threshold {
            group_by: &["IpAddress"],
            distinct: Some("TargetUserName"),
            min: 3,
            window_secs: 60,
        }),
        false_positives: "",
        references: &[],
    };

    #[test]
    fn threshold_distinct_in_window() {
        let mut keys = KeyInterner::default();
        let recs = vec![
            failed_logon(1, "2024-01-01T10:00:00Z", "10.0.0.9", "alice", &mut keys),
            failed_logon(2, "2024-01-01T10:00:10Z", "10.0.0.9", "bob", &mut keys),
            failed_logon(3, "2024-01-01T10:00:20Z", "10.0.0.9", "carol", &mut keys),
            // Same IP but far outside the window.
            failed_logon(4, "2024-01-01T12:00:00Z", "10.0.0.9", "dave", &mut keys),
            // Different IP, only repeats one user.
            failed_logon(5, "2024-01-01T10:00:00Z", "10.0.0.7", "alice", &mut keys),
            failed_logon(6, "2024-01-01T10:00:01Z", "10.0.0.7", "alice", &mut keys),
            failed_logon(7, "2024-01-01T10:00:02Z", "10.0.0.7", "alice", &mut keys),
        ];
        let keys_lc: Vec<Box<str>> = keys
            .take_new()
            .iter()
            .map(|k| k.to_lowercase().into())
            .collect();
        let (hits, errors) = run(&[DetRule::from_builtin(&SPRAY)], &recs, &keys_lc);
        assert!(errors.is_empty());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].records, vec![0, 1, 2]);
    }

    #[test]
    fn threshold_is_linear_on_huge_spray() {
        let mut keys = KeyInterner::default();
        let n = 200_000;
        let recs: Vec<Record> = (0..n)
            .map(|i| {
                let t = format!(
                    "2024-01-01T{:02}:{:02}:{:02}Z",
                    (i / 3600) % 24,
                    (i / 60) % 60,
                    i % 60
                );
                failed_logon(
                    i as u64,
                    &t,
                    "10.0.0.9",
                    &format!("user{}", i % 50),
                    &mut keys,
                )
            })
            .collect();
        let keys_lc: Vec<Box<str>> = keys
            .take_new()
            .iter()
            .map(|k| k.to_lowercase().into())
            .collect();
        let t = std::time::Instant::now();
        let (hits, _) = run(&[DetRule::from_builtin(&SPRAY)], &recs, &keys_lc);
        assert_eq!(hits[0].records.len(), n);
        assert!(t.elapsed().as_secs() < 10, "took {:?}", t.elapsed());
    }

    #[test]
    fn all_builtin_rules_compile() {
        let (_, errors) = run(&builtin_rules(), &[], &[]);
        assert!(errors.is_empty(), "{errors:?}");
        let mut ids: Vec<&str> = crate::rules::RULES.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(n, ids.len(), "duplicate rule ids");
        for r in crate::rules::RULES {
            assert!(!r.event_ids.is_empty(), "{} has no event IDs", r.id);
            assert!(!r.references.is_empty(), "{} has no references", r.id);
            let drl_source = r
                .references
                .iter()
                .any(|u| u.contains("SigmaHQ/sigma") || u.contains("hayabusa-rules"));
            assert!(
                !drl_source || !r.author.is_empty(),
                "{} adapts a DRL rule but credits no author",
                r.id
            );
        }
    }

    /// `SIGMA_DIR=sigma/rules EVTX_SAMPLE=file EVTX_N=300000 cargo test --release sigma_scale -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn sigma_scale() {
        let (Ok(dir), Ok(sample)) = (std::env::var("SIGMA_DIR"), std::env::var("EVTX_SAMPLE"))
        else {
            return;
        };
        let n: usize = std::env::var("EVTX_N")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300_000);
        let t = std::time::Instant::now();
        let report = crate::sigma::load_dir(std::path::Path::new(&dir));
        let mut rules = builtin_rules();
        let imported = report.rules.len();
        rules.extend(
            report
                .rules
                .into_iter()
                .map(|r| DetRule::from_sigma(r, report.drl)),
        );
        println!(
            "loaded {imported} Sigma rules ({} skipped) in {:?}",
            report.skipped.len(),
            t.elapsed()
        );

        let mut parser = evtx::EvtxParser::from_path(&sample).unwrap();
        let raw: Vec<_> = parser.records_json_value().filter_map(Result::ok).collect();
        let mut keys = crate::model::KeyInterner::default();
        let mut records = Vec::with_capacity(n);
        'outer: loop {
            for r in &raw {
                if records.len() == n {
                    break 'outer;
                }
                records.push(
                    crate::model::Draft::new(
                        records.len() as u64,
                        0,
                        r.timestamp.to_string(),
                        r.data.clone(),
                    )
                    .finish(&mut keys),
                );
            }
        }
        let keys_lc: Vec<Box<str>> = keys
            .take_new()
            .iter()
            .map(|k| k.to_lowercase().into())
            .collect();
        let t = std::time::Instant::now();
        let (hits, errors) = run(&rules, &records, &keys_lc);
        println!(
            "{} rules over {} records: {:?}, {} rules matched, {} errors",
            rules.len(),
            records.len(),
            t.elapsed(),
            hits.len(),
            errors.len()
        );
        let mut names: Vec<(usize, &str)> = hits
            .iter()
            .map(|h| (h.records.len(), rules[h.rule].name.as_str()))
            .collect();
        names.sort_unstable_by(|a, b| b.cmp(a));
        for (count, name) in names.iter().take(15) {
            println!("  {count:7}  {name}");
        }
    }
}
