use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;

use evtx::{EvtxChunkData, ParserSettings};
use rayon::prelude::*;

use crate::model::{Draft, KeyInterner, Record};

const CHUNK_SIZE: u64 = 65536;

/// Parsed EVTX file header (the crate keeps its own header type private).
#[derive(Clone, Debug)]
pub struct FileInfo {
    pub size: u64,
    pub major_version: u16,
    pub minor_version: u16,
    pub header_block_size: u16,
    pub chunk_count: u16,
    pub first_chunk: u64,
    pub last_chunk: u64,
    pub next_record_id: u64,
    pub dirty: bool,
    pub full: bool,
}

impl FileInfo {
    pub fn read(path: &Path) -> Result<Self, String> {
        let mut f =
            File::open(path).map_err(|e| format!("Failed to open {}: {e}", path.display()))?;
        let size = f.metadata().map_err(|e| e.to_string())?.len();
        let mut h = [0u8; 128];
        f.read_exact(&mut h)
            .map_err(|_| "File is too small to be an EVTX log".to_string())?;
        if &h[..8] != b"ElfFile\0" {
            return Err(format!(
                "{} is not an EVTX file (bad signature)",
                path.display()
            ));
        }
        let u16_at = |o: usize| u16::from_le_bytes([h[o], h[o + 1]]);
        let u32_at = |o: usize| u32::from_le_bytes(h[o..o + 4].try_into().unwrap());
        let u64_at = |o: usize| u64::from_le_bytes(h[o..o + 8].try_into().unwrap());
        let flags = u32_at(120);
        Ok(Self {
            size,
            first_chunk: u64_at(8),
            last_chunk: u64_at(16),
            next_record_id: u64_at(24),
            minor_version: u16_at(36),
            major_version: u16_at(38),
            header_block_size: u16_at(40).max(128),
            chunk_count: u16_at(42),
            dirty: flags & 1 != 0,
            full: flags & 2 != 0,
        })
    }

    /// Chunks physically present. Like the evtx crate, this is computed from the file size
    /// rather than trusting the header, so logs past the header's u16 limit still parse.
    fn chunks_in_file(&self) -> u64 {
        self.size.saturating_sub(self.header_block_size as u64) / CHUNK_SIZE
    }
}

pub enum Msg {
    Info(FileInfo),
    Records {
        records: Vec<Record>,
        new_keys: Vec<Box<str>>,
    },
    RecordError(String),
    Done,
    Fatal(String),
}

/// Parse `path` on a background thread. Dropping the returned receiver cancels the load.
pub fn spawn(path: PathBuf, ctx: eframe::egui::Context) -> Receiver<Msg> {
    let (tx, rx) = mpsc::channel();
    let _ = thread::Builder::new()
        .name("evtx-loader".into())
        .stack_size(16 << 20)
        .spawn(move || {
            match run(&path, &tx, &ctx) {
                Ok(()) => {}
                Err(e) => {
                    let _ = tx.send(Msg::Fatal(e));
                }
            }
            ctx.request_repaint();
        });
    rx
}

fn settings(pretty: bool) -> Arc<ParserSettings> {
    Arc::new(ParserSettings::new().num_threads(0).indent(pretty))
}

fn read_chunk(f: &mut File, info: &FileInfo, n: u64) -> std::io::Result<Option<Vec<u8>>> {
    f.seek(SeekFrom::Start(
        info.header_block_size as u64 + n * CHUNK_SIZE,
    ))?;
    let mut data = vec![0u8; CHUNK_SIZE as usize];
    f.read_exact(&mut data)?;
    // Unused chunks at the end of a log are zero-filled; skip them quietly.
    Ok((&data[..8] == b"ElfChnk\0").then_some(data))
}

/// [`parse_chunk`], but a crash inside the parser on a malformed chunk becomes an error for
/// that chunk instead of taking down the whole load.
fn parse_chunk_guarded(n: u64, data: Vec<u8>) -> Vec<Result<Draft, String>> {
    std::panic::catch_unwind(move || parse_chunk(n, data)).unwrap_or_else(|_| {
        vec![Err(format!(
            "chunk {n}: parser crashed on malformed data; chunk skipped"
        ))]
    })
}

/// Parse one chunk into drafts (or error messages).
fn parse_chunk(n: u64, data: Vec<u8>) -> Vec<Result<Draft, String>> {
    let mut chunk_data = match EvtxChunkData::new(data, false) {
        Ok(c) => c,
        Err(e) => return vec![Err(format!("chunk {n}: {e}"))],
    };
    let mut chunk = match chunk_data.parse(settings(false)) {
        Ok(c) => c,
        Err(e) => return vec![Err(format!("chunk {n}: {e}"))],
    };
    chunk
        .iter()
        .map(|rec| {
            let r = match rec {
                Ok(r) => r.into_json_value(),
                Err(e) => Err(e),
            }
            .map_err(|e| format!("chunk {n}: {e}"))?;
            Ok(Draft::new(
                r.event_record_id,
                n as u32,
                r.timestamp.to_string(),
                r.data,
            ))
        })
        .collect()
}

/// Returns Err only for fatal errors; a closed channel just means the user moved on.
fn run(path: &Path, tx: &Sender<Msg>, ctx: &eframe::egui::Context) -> Result<(), String> {
    let send = |m: Msg| {
        let ok = tx.send(m).is_ok();
        ctx.request_repaint();
        ok
    };

    let info = FileInfo::read(path)?;
    let total = info.chunks_in_file();
    send(Msg::Info(info.clone()));

    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut keys = KeyInterner::default();
    // Read a batch of chunks sequentially, then parse them in parallel.
    let batch_size = (rayon::current_num_threads() * 4).max(8) as u64;
    let mut next = 0;
    while next < total {
        let end = (next + batch_size).min(total);
        let mut raw = Vec::with_capacity((end - next) as usize);
        for n in next..end {
            match read_chunk(&mut file, &info, n) {
                Ok(Some(data)) => raw.push((n, data)),
                Ok(None) => {}
                Err(e) => {
                    if !send(Msg::RecordError(format!("chunk {n}: {e}"))) {
                        return Ok(());
                    }
                }
            }
        }
        next = end;

        let parsed: Vec<Vec<Result<Draft, String>>> = raw
            .into_par_iter()
            .map(|(n, data)| parse_chunk_guarded(n, data))
            .collect();

        let mut records = Vec::new();
        for result in parsed.into_iter().flatten() {
            match result {
                Ok(d) => records.push(d.finish(&mut keys)),
                Err(e) => {
                    if !send(Msg::RecordError(e)) {
                        return Ok(());
                    }
                }
            }
        }
        if !send(Msg::Records {
            records,
            new_keys: keys.take_new(),
        }) {
            return Ok(());
        }
    }
    send(Msg::Done);
    Ok(())
}

/// Format to render a record in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Render {
    Xml,
    JsonPretty,
    JsonLine,
}

/// Re-render records from their chunks. `wanted` is (chunk, record_id) pairs; each chunk is
/// read and parsed once.
pub fn render(
    path: &Path,
    wanted: &[(u32, u64)],
    format: Render,
) -> Result<HashMap<(u32, u64), String>, String> {
    // Runs on the UI thread: never let a parser crash on a malformed chunk take the app down.
    std::panic::catch_unwind(|| render_unguarded(path, wanted, format))
        .unwrap_or_else(|_| Err("the parser crashed on malformed data in this chunk".to_string()))
}

fn render_unguarded(
    path: &Path,
    wanted: &[(u32, u64)],
    format: Render,
) -> Result<HashMap<(u32, u64), String>, String> {
    let info = FileInfo::read(path)?;
    let mut by_chunk: HashMap<u32, Vec<u64>> = HashMap::new();
    for &(c, id) in wanted {
        by_chunk.entry(c).or_default().push(id);
    }
    let mut chunks: Vec<_> = by_chunk.into_iter().collect();
    chunks.sort_unstable_by_key(|(c, _)| *c);

    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut out = HashMap::with_capacity(wanted.len());
    for (c, ids) in chunks {
        let Some(data) = read_chunk(&mut file, &info, c as u64).map_err(|e| e.to_string())? else {
            continue;
        };
        let mut chunk_data = EvtxChunkData::new(data, false).map_err(|e| e.to_string())?;
        let mut chunk = chunk_data
            .parse(settings(format == Render::JsonPretty))
            .map_err(|e| e.to_string())?;
        for rec in chunk.iter().flatten() {
            let id = rec.event_record_id;
            if !ids.contains(&id) {
                continue;
            }
            let text = match format {
                Render::Xml => rec.into_xml().map(|r| r.data),
                Render::JsonPretty | Render::JsonLine => rec.into_json().map(|r| r.data),
            };
            if let Ok(t) = text {
                out.insert((c, id), t);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses a real file when EVTX_SAMPLE is set and checks we see the same records as
    /// the evtx crate's own iterator.
    #[test]
    fn matches_crate_parser() {
        let Ok(path) = std::env::var("EVTX_SAMPLE") else {
            return;
        };
        let path = PathBuf::from(path);
        let info = FileInfo::read(&path).unwrap();
        let mut file = File::open(&path).unwrap();
        let mut keys = KeyInterner::default();
        let mut ours = Vec::new();
        for n in 0..info.chunks_in_file() {
            if let Some(data) = read_chunk(&mut file, &info, n).unwrap() {
                ours.extend(
                    parse_chunk(n, data)
                        .into_iter()
                        .map(|d| d.unwrap().finish(&mut keys)),
                );
            }
        }
        let mut parser = evtx::EvtxParser::from_path(&path).unwrap();
        let theirs: Vec<u64> = parser
            .records_json_value()
            .filter_map(Result::ok)
            .map(|r| r.event_record_id)
            .collect();
        assert_eq!(ours.iter().map(|r| r.record_id).collect::<Vec<_>>(), theirs);
        println!("{} records, {} chunks", ours.len(), info.chunks_in_file());

        let r = &ours[ours.len() / 2];
        let xml = render(&path, &[(r.chunk, r.record_id)], Render::Xml).unwrap();
        let xml = &xml[&(r.chunk, r.record_id)];
        let erid = r.col(crate::model::Col::EventRecordId);
        assert!(
            xml.contains(&format!("<EventRecordID>{erid}</EventRecordID>")),
            "{xml}"
        );
        let json = render(&path, &[(r.chunk, r.record_id)], Render::JsonPretty).unwrap();
        assert!(json[&(r.chunk, r.record_id)].contains("\"EventRecordID\""));
    }
}

/// Load every record of a file with the app's own loader (for tests and tools).
#[cfg(test)]
pub fn load_records(path: &Path) -> Result<(Vec<Record>, Vec<Box<str>>), String> {
    let info = FileInfo::read(path)?;
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut keys = KeyInterner::default();
    let mut recs = Vec::new();
    for n in 0..info.chunks_in_file() {
        if let Some(data) = read_chunk(&mut file, &info, n).map_err(|e| e.to_string())? {
            recs.extend(
                parse_chunk_guarded(n, data)
                    .into_iter()
                    .flatten()
                    .map(|d| d.finish(&mut keys)),
            );
        }
    }
    let keys_lc = keys
        .take_new()
        .iter()
        .map(|k| k.to_lowercase().into())
        .collect();
    Ok((recs, keys_lc))
}

#[cfg(test)]
mod fuzz {
    use super::*;

    /// Corrupt real chunks in many deterministic ways and make sure parsing never escapes
    /// the guard, and that nothing downstream (record building, timestamps) panics.
    /// `EVTX_SAMPLE=file cargo test --release fuzz -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn mutated_chunks() {
        let Ok(path) = std::env::var("EVTX_SAMPLE") else {
            return;
        };
        let path = PathBuf::from(path);
        let info = FileInfo::read(&path).unwrap();
        let mut file = File::open(&path).unwrap();
        let chunks: Vec<Vec<u8>> = (0..info.chunks_in_file())
            .filter_map(|n| read_chunk(&mut file, &info, n).unwrap())
            .take(4)
            .collect();
        assert!(!chunks.is_empty());
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let (mut ok_records, mut errors, mut crashes_contained) = (0usize, 0usize, 0usize);
        let mut keys = KeyInterner::default();
        for round in 0..400 {
            let mut data = chunks[round % chunks.len()].clone();
            match round % 4 {
                // Flip random bytes in the record area.
                0 | 1 => {
                    for _ in 0..(1 + next() % 32) {
                        let i = 512 + (next() as usize % (data.len() - 512));
                        data[i] ^= (next() & 0xff) as u8 | 1;
                    }
                }
                // Overwrite a random span with garbage.
                2 => {
                    let start = 512 + (next() as usize % (data.len() - 600));
                    for b in &mut data[start..start + 64] {
                        *b = next() as u8;
                    }
                }
                // Corrupt the chunk header's offsets.
                _ => {
                    for i in [40usize, 44, 48] {
                        data[i] = next() as u8;
                    }
                }
            }
            for r in parse_chunk_guarded(round as u64, data) {
                match r {
                    Ok(d) => {
                        let rec = d.finish(&mut keys);
                        let _ = crate::detect::parse_timestamp(&rec.timestamp);
                        ok_records += 1;
                    }
                    Err(e) if e.contains("parser crashed") => crashes_contained += 1,
                    Err(_) => errors += 1,
                }
            }
        }
        println!("{ok_records} records parsed, {errors} clean errors, {crashes_contained} parser crashes contained");
    }
}

#[cfg(test)]
mod corpus {
    use super::*;
    use std::collections::BTreeMap;

    fn evtx_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                evtx_files(&p, out);
            } else if p
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("evtx"))
            {
                out.push(p);
            }
        }
    }

    /// Parse every .evtx under EVTX_DIR with the app's loader, run all detection rules, and
    /// report per-rule hits. Fails if parsing panics on any file.
    /// `EVTX_DIR=dir cargo test --release corpus -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn corpus() {
        let Ok(dir) = std::env::var("EVTX_DIR") else {
            return;
        };
        let mut files = Vec::new();
        evtx_files(Path::new(&dir), &mut files);
        files.sort();
        let mut by_rule: BTreeMap<&str, (usize, Vec<String>)> = BTreeMap::new();
        let (mut total, mut errors, mut panics, mut rejected) =
            (0usize, 0usize, Vec::new(), 0usize);
        for f in &files {
            let result = std::panic::catch_unwind(|| {
                let Ok(info) = FileInfo::read(f) else {
                    return None;
                };
                let mut file = File::open(f).ok()?;
                let mut keys = KeyInterner::default();
                let (mut recs, mut errs) = (Vec::new(), 0);
                for n in 0..info.chunks_in_file() {
                    match read_chunk(&mut file, &info, n) {
                        Ok(Some(data)) => {
                            for d in parse_chunk(n, data) {
                                match d {
                                    Ok(d) => recs.push(d.finish(&mut keys)),
                                    Err(_) => errs += 1,
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(_) => errs += 1,
                    }
                }
                let keys_lc: Vec<Box<str>> = keys
                    .take_new()
                    .iter()
                    .map(|k| k.to_lowercase().into())
                    .collect();
                let (hits, rule_errors) =
                    crate::detect::run(&crate::detect::builtin_rules(), &recs, &keys_lc);
                assert!(rule_errors.is_empty(), "{rule_errors:?}");
                Some((recs.len(), errs, hits))
            });
            match result {
                Ok(Some((n, errs, hits))) => {
                    total += n;
                    errors += errs;
                    let name = f.file_name().unwrap().to_string_lossy().into_owned();
                    for h in hits {
                        let e = by_rule.entry(crate::rules::RULES[h.rule].id).or_default();
                        e.0 += h.records.len();
                        if e.1.len() < 4 {
                            e.1.push(format!("{name} ({})", h.records.len()));
                        }
                    }
                }
                Ok(None) => rejected += 1,
                Err(_) => panics.push(f.display().to_string()),
            }
        }
        println!(
            "{} files ({rejected} not EVTX), {total} records, {errors} record/chunk errors",
            files.len()
        );
        for (rule, (n, examples)) in &by_rule {
            println!("{rule:35} {n:6}  {}", examples.join(", "));
        }
        let silent: Vec<&str> = crate::rules::RULES
            .iter()
            .map(|r| r.id)
            .filter(|id| !by_rule.contains_key(id))
            .collect();
        println!("rules with no hits: {silent:?}");
        assert!(panics.is_empty(), "parser panicked on: {panics:#?}");
    }
}
