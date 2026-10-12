//! The set of open files ("sources") and the folder shown in the file explorer.

use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use crate::loader::{FileInfo, Msg};

/// One open .evtx file and its loading state.
pub struct Source {
    pub path: PathBuf,
    pub name: String,
    pub info: Option<FileInfo>,
    /// Live while the file is being parsed; dropping it cancels the load.
    pub rx: Option<Receiver<Msg>>,
    /// The loader numbers field names on its own; this maps its ids to the app's shared ids.
    pub key_map: Vec<u32>,
    pub events: usize,
    pub errors: usize,
    pub last_error: Option<String>,
    pub fatal: Option<String>,
    pub started: Instant,
    pub load_time: Option<Duration>,
}

impl Source {
    pub fn new(path: PathBuf, rx: Receiver<Msg>) -> Self {
        Self {
            name: display_name(&path),
            path,
            info: None,
            rx: Some(rx),
            key_map: Vec::new(),
            events: 0,
            errors: 0,
            last_error: None,
            fatal: None,
            started: Instant::now(),
            load_time: None,
        }
    }

    pub fn done(&self) -> bool {
        self.rx.is_none()
    }
}

pub fn display_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

/// An .evtx file found in the explorer's folder.
pub struct FolderFile {
    pub path: PathBuf,
    /// Path of the containing directory relative to the folder ("" for the folder itself).
    pub dir: String,
    pub name: String,
    pub size: u64,
}

pub struct Folder {
    pub path: PathBuf,
    pub files: Vec<FolderFile>,
    /// The scan stopped early because the folder is very large.
    pub truncated: bool,
}

const MAX_DEPTH: usize = 8;
const MAX_FILES: usize = 5_000;
const MAX_ENTRIES: usize = 200_000;

/// Find .evtx files under `dir` (recursively, without following symlinks or entering
/// hidden folders), sorted by relative path.
pub fn scan(dir: &Path) -> Folder {
    let mut files = Vec::new();
    let mut seen = 0usize;
    let mut truncated = false;
    walk(dir, dir, 0, &mut files, &mut seen, &mut truncated);
    files.sort_by(|a: &FolderFile, b: &FolderFile| {
        (a.dir.to_lowercase(), a.name.to_lowercase())
            .cmp(&(b.dir.to_lowercase(), b.name.to_lowercase()))
    });
    Folder {
        path: dir.to_path_buf(),
        files,
        truncated,
    }
}

fn walk(
    root: &Path,
    dir: &Path,
    depth: usize,
    out: &mut Vec<FolderFile>,
    seen: &mut usize,
    truncated: &mut bool,
) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut subdirs = Vec::new();
    for e in entries.flatten() {
        *seen += 1;
        if out.len() >= MAX_FILES || *seen > MAX_ENTRIES {
            *truncated = true;
            return;
        }
        let p = e.path();
        let Ok(meta) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        let name = e.file_name().to_string_lossy().into_owned();
        if meta.is_dir() {
            if !name.starts_with('.') {
                subdirs.push(p);
            }
        } else if meta.is_file()
            && p.extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("evtx"))
        {
            let rel = dir.strip_prefix(root).unwrap_or(Path::new(""));
            out.push(FolderFile {
                dir: rel.to_string_lossy().into_owned(),
                name,
                size: meta.len(),
                path: p,
            });
        }
    }
    subdirs.sort();
    for d in subdirs {
        walk(root, &d, depth + 1, out, seen, truncated);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_nested_evtx_files_only() {
        let root = std::env::temp_dir().join(format!("tw-scan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("DC01/logs")).unwrap();
        std::fs::create_dir_all(root.join(".hidden")).unwrap();
        for p in [
            "Security.evtx",
            "DC01/System.EVTX",
            "DC01/logs/Sysmon.evtx",
            "notes.txt",
            ".hidden/x.evtx",
        ] {
            std::fs::write(root.join(p), b"x").unwrap();
        }
        std::os::unix::fs::symlink(root.join("Security.evtx"), root.join("link.evtx")).unwrap();
        let f = scan(&root);
        let got: Vec<String> = f
            .files
            .iter()
            .map(|f| format!("{}|{}", f.dir, f.name))
            .collect();
        assert_eq!(
            got,
            [
                "|Security.evtx",
                "DC01|System.EVTX",
                "DC01/logs|Sysmon.evtx"
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
