//! In-app updates from GitHub Releases.
//!
//! Flow: ask the GitHub API for the latest release → download that release's
//! `Tidewatch.zip` and `SHA256SUMS.txt` → verify the checksum, the code signature, the bundle
//! identifier and the version → swap the new bundle in next to the running one (keeping the
//! old one until the swap succeeds) → relaunch.
//!
//! Downloads use the system `curl`, like the installer, so no HTTP or TLS code ships in the
//! app and downloaded files aren't quarantined. The only data sent is the request itself.

use std::path::{Path, PathBuf};
use std::process::Command;

const REPO: &str = "Nyanites/tidewatch";
const BUNDLE_ID: &str = "dev.tidewatch";
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug)]
pub struct Release {
    pub version: String,
    pub notes: String,
    pub url: String,
}

impl Release {
    pub fn is_newer(&self) -> bool {
        is_newer(&self.version, CURRENT)
    }
}

/// Ask GitHub for the latest published release.
pub fn latest() -> Result<Release, String> {
    let out = Command::new("/usr/bin/curl")
        .args([
            "-fsSL",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--max-time",
            "20",
        ])
        .args(["-H", "Accept: application/vnd.github+json"])
        .args(["-H", &format!("User-Agent: Tidewatch/{CURRENT}")])
        .arg(format!(
            "https://api.github.com/repos/{REPO}/releases/latest"
        ))
        .output()
        .map_err(|e| format!("couldn't run curl: {e}"))?;
    if !out.status.success() {
        return Err("couldn't reach GitHub (are you offline?)".into());
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|_| "unexpected reply from GitHub".to_string())?;
    let tag = v["tag_name"].as_str().unwrap_or_default();
    let version = tag.strip_prefix('v').unwrap_or(tag).to_string();
    if !valid_version(&version) {
        return Err(format!("unexpected release tag {tag:?}"));
    }
    let mut notes = v["body"].as_str().unwrap_or_default().trim().to_string();
    if notes.len() > 4000 {
        let mut cut = 4000;
        while !notes.is_char_boundary(cut) {
            cut -= 1;
        }
        notes.truncate(cut);
        notes.push('…');
    }
    Ok(Release {
        version,
        notes,
        url: format!("https://github.com/{REPO}/releases/tag/{tag}"),
    })
}

fn valid_version(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 32
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Numeric comparison of dotted versions; pre-release suffixes (`-beta`) sort before the
/// plain version.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    fn parse(v: &str) -> (Vec<u64>, bool) {
        let (core, pre) = match v.split_once('-') {
            Some((c, _)) => (c, true),
            None => (v, false),
        };
        (
            core.split('.').map(|p| p.parse().unwrap_or(0)).collect(),
            pre,
        )
    }
    let ((a, a_pre), (b, b_pre)) = (parse(candidate), parse(current));
    let n = a.len().max(b.len());
    for i in 0..n {
        let (x, y) = (
            a.get(i).copied().unwrap_or(0),
            b.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return x > y;
        }
    }
    // Same numbers: a release beats its pre-release.
    b_pre && !a_pre
}

/// The `.app` bundle this process runs from, if any (not when started with `cargo run`).
pub fn bundle_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let app = contents.parent()?;
    (macos.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && app.extension().is_some_and(|e| e == "app"))
    .then(|| app.to_path_buf())
}

/// Where the previous version is parked during an update (next to the bundle, same volume).
fn backup_path(bundle: &Path) -> Option<PathBuf> {
    Some(
        bundle
            .parent()?
            .join(format!(".{}.old", bundle.file_name()?.to_string_lossy())),
    )
}

fn staging_dir(bundle: &Path) -> Option<PathBuf> {
    Some(bundle.parent()?.join(".tidewatch-update"))
}

/// Remove leftovers of a previous update. Call at startup.
pub fn cleanup() {
    let Some(bundle) = bundle_path() else { return };
    for p in [backup_path(&bundle), staging_dir(&bundle)]
        .into_iter()
        .flatten()
    {
        if p.exists() {
            let _ = std::fs::remove_dir_all(&p);
        }
    }
}

/// Download, verify and install `release` over the running bundle. On success the new
/// version is in place and the caller should relaunch.
pub fn install(release: &Release) -> Result<PathBuf, String> {
    let bundle = bundle_path().ok_or(
        "Tidewatch isn't running from an app bundle; update with the install command instead",
    )?;
    let parent = bundle.parent().ok_or("bad app location")?;
    let probe = parent.join(".tidewatch-write-test");
    std::fs::write(&probe, b"").map_err(|_| {
        format!(
            "can't write to {}; update with the install command instead",
            parent.display()
        )
    })?;
    let _ = std::fs::remove_file(&probe);

    let staging = staging_dir(&bundle).ok_or("bad app location")?;
    if staging.exists() {
        std::fs::remove_dir_all(&staging).map_err(|e| e.to_string())?;
    }
    std::fs::create_dir(&staging).map_err(|e| e.to_string())?;
    let result = stage_and_swap(release, &bundle, &staging);
    let _ = std::fs::remove_dir_all(&staging);
    result.map(|()| bundle)
}

fn stage_and_swap(release: &Release, bundle: &Path, staging: &Path) -> Result<(), String> {
    if !valid_version(&release.version) {
        return Err("invalid version".into());
    }
    let base = format!(
        "https://github.com/{REPO}/releases/download/v{}",
        release.version
    );
    let zip = staging.join("Tidewatch.zip");
    let sums = staging.join("SHA256SUMS.txt");
    download(&format!("{base}/Tidewatch.zip"), &zip)?;
    download(&format!("{base}/SHA256SUMS.txt"), &sums)?;

    // 1. Checksum published with the release.
    let sums = std::fs::read_to_string(&sums).map_err(|e| e.to_string())?;
    let expected = sums
        .lines()
        .find_map(|l| {
            let mut it = l.split_whitespace();
            let (hash, name) = (it.next()?, it.next()?);
            (name == "Tidewatch.zip").then(|| hash.to_ascii_lowercase())
        })
        .ok_or("the release has no checksum for Tidewatch.zip")?;
    let out = run("/usr/bin/shasum", &["-a", "256"], Some(&zip))?;
    let actual = out
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if actual != expected {
        return Err("the download didn't match its published checksum; nothing was changed".into());
    }

    // 2. Unpack and check it really is the expected Tidewatch build.
    let unpacked = staging.join("unpacked");
    run_ok("/usr/bin/ditto", &["-x", "-k"], &[&zip, &unpacked])?;
    let new_app = unpacked.join("Tidewatch.app");
    if !new_app.is_dir() {
        return Err("Tidewatch.app wasn't found in the download".into());
    }
    let plist = new_app.join("Contents/Info.plist");
    let id = plist_value(&plist, "CFBundleIdentifier")?;
    let ver = plist_value(&plist, "CFBundleShortVersionString")?;
    if id != BUNDLE_ID || ver != release.version {
        return Err(format!("unexpected app in the download ({id} {ver})"));
    }
    run_ok(
        "/usr/bin/codesign",
        &["--verify", "--strict", "--deep"],
        &[&new_app],
    )
    .map_err(|_| "the downloaded app's code signature is invalid".to_string())?;

    // 3. Swap: park the running bundle, move the new one in, restore on failure.
    let backup = backup_path(bundle).ok_or("bad app location")?;
    if backup.exists() {
        std::fs::remove_dir_all(&backup).map_err(|e| e.to_string())?;
    }
    std::fs::rename(bundle, &backup).map_err(|e| format!("couldn't replace the app: {e}"))?;
    if let Err(e) = std::fs::rename(&new_app, bundle) {
        let _ = std::fs::rename(&backup, bundle);
        return Err(format!("couldn't replace the app: {e}"));
    }
    // Let Finder pick up the new bundle (document icons, .evtx association).
    let _ = Command::new(
        "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister",
    )
    .arg("-f")
    .arg(bundle)
    .output();
    Ok(())
}

/// Start the installed bundle as a new process (the caller then quits).
pub fn relaunch(bundle: &Path) -> Result<(), String> {
    Command::new("/usr/bin/open")
        .arg("-n")
        .arg(bundle)
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn download(url: &str, to: &Path) -> Result<(), String> {
    let status = Command::new("/usr/bin/curl")
        .args([
            "-fsSL",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--retry",
            "2",
            "--max-time",
            "300",
        ])
        .arg("-o")
        .arg(to)
        .arg(url)
        .status()
        .map_err(|e| format!("couldn't run curl: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("download failed (are you offline?)".into())
    }
}

fn run(cmd: &str, args: &[&str], path: Option<&Path>) -> Result<String, String> {
    let mut c = Command::new(cmd);
    c.args(args);
    if let Some(p) = path {
        c.arg(p);
    }
    let out = c.output().map_err(|e| format!("couldn't run {cmd}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{cmd} failed"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn run_ok(cmd: &str, args: &[&str], paths: &[&Path]) -> Result<(), String> {
    let out = Command::new(cmd)
        .args(args)
        .args(paths)
        .output()
        .map_err(|e| format!("couldn't run {cmd}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{cmd} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

fn plist_value(plist: &Path, key: &str) -> Result<String, String> {
    Ok(run(
        "/usr/bin/plutil",
        &["-extract", key, "raw", "-o", "-"],
        Some(plist),
    )?
    .trim()
    .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_ordering() {
        assert!(is_newer("0.1.3", "0.1.2"));
        assert!(is_newer("0.2.0", "0.1.9"));
        assert!(is_newer("1.0", "0.9.9"));
        assert!(
            is_newer("0.1.10", "0.1.9"),
            "numeric, not string, comparison"
        );
        assert!(!is_newer("0.1.2", "0.1.2"));
        assert!(!is_newer("0.1.1", "0.1.2"));
        assert!(is_newer("0.2.0", "0.2.0-beta"));
        assert!(!is_newer("0.2.0-beta", "0.2.0"));
    }

    #[test]
    fn rejects_odd_tags() {
        assert!(valid_version("0.1.3"));
        assert!(!valid_version("0.1.3; rm -rf"));
        assert!(!valid_version("../../x"));
        assert!(!valid_version(""));
    }
}
