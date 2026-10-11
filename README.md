# Tidewatch

A fast, native Windows Event Log (`.evtx`) viewer and threat-hunting tool for macOS, written in Rust.

**[⬇ Download Tidewatch for macOS](https://github.com/Nyanites/tidewatch/releases/latest/download/Tidewatch.dmg)** · [Website](https://nyanites.github.io/tidewatch/)

One 7 MB app that runs on Apple Silicon and Intel Macs (macOS 11 or newer). There's nothing else to install.

Open a `.evtx` file pulled from a Windows machine and search, filter and read its events. You don't need Windows, a VM or Event Viewer. It's built for incident responders and threat hunters who triage logs on a Mac.

- **Fast.** The file is read in parallel on every CPU core. Searching 500,000 events takes a few milliseconds.
- **Readable without Windows.** Common event IDs come with built-in descriptions, and codes are decoded inline (logon types, Kerberos encryption types, NTSTATUS failure codes, well-known SIDs, keywords).
- **Built for searching.** Plain text, quoted phrases, exclusions, field-scoped matches and full regex, with matches highlighted in the event details.
- **Finds suspicious activity for you.** Built-in detections flag things like Kerberoasting, password spraying, DCSync, lateral movement, cleared logs and Defender tampering, and you can import the full [Sigma](https://github.com/SigmaHQ/sigma) rule library (thousands of community rules) in two clicks.
- **Shows everything.** Every `System`, `EventData`, `UserData` and extra element (e.g. `RenderingInfo`) is displayed, plus the raw JSON and XML.

---

## Contents

- [Install](#install)
- [Opening logs](#opening-logs)
- [Searching](#searching)
- [Filters](#filters)
- [Reading an event](#reading-an-event)
- [Detections](#detections)
- [Log Summary](#log-summary)
- [Export](#export)
- [Keyboard shortcuts](#keyboard-shortcuts)
- [Performance](#performance)
- [How it works](#how-it-works)
- [Limitations](#limitations)
- [Development](#development)
- [Releasing](#releasing)
- [License](#license)

---

## Install

**Option 1: one command (recommended).** Open Terminal and paste:

```bash
curl -fsSL https://nyanites.github.io/tidewatch/install.sh | bash
```

The [installer](docs/install.sh) downloads the latest release from GitHub, checks it against the published SHA-256 checksum, and copies Tidewatch into Applications. It never asks for your password. Run it again to update. To install a specific version, prefix the command with `TIDEWATCH_VERSION=0.1.0`.

**Option 2: disk image.**

1. Download **[Tidewatch.dmg](https://github.com/Nyanites/tidewatch/releases/latest/download/Tidewatch.dmg)** from the [latest release](https://github.com/Nyanites/tidewatch/releases/latest).
2. Open the `.dmg` and drag **Tidewatch** onto **Applications**.
3. The first time you open it, macOS says it can't verify the developer, because Tidewatch isn't notarized by Apple. Click **Done**, go to **System Settings → Privacy & Security**, and click **Open Anyway**. You only need to do this once.

**Uninstall:** drag Tidewatch from Applications to the Trash.

<details>
<summary>Build from source instead</summary>

Requires the [Rust toolchain](https://rustup.rs) (1.87 or newer) and Xcode Command Line Tools (`xcode-select --install`).

```bash
git clone https://github.com/Nyanites/tidewatch.git
cd tidewatch
./bundle-macos.sh --dmg          # builds target/Tidewatch.app and target/Tidewatch-<version>.dmg
```

Add `--universal` for an app that runs on both Apple Silicon and Intel. To run without bundling: `cargo run --release -- path/to/Security.evtx`.

</details>

## Opening logs

- **Double-click** a `.evtx` file in Finder, or right-click it → **Open With → Tidewatch**
- Drag a `.evtx` file onto the window or the Dock icon
- **File → Open…** or **⌘O**
- **File → Open Recent**, or the recent list on the start screen

Rows appear while the file is still loading. Damaged records are skipped and counted in the status bar; hover the count to see the last error.

## Searching

The search box has two modes, **Text** and **.\* Regex**. The **Aa** button turns on case-sensitive matching. **⌘F** jumps to the search box.

### Text mode

All terms must match (AND).

| Query | Matches events where… |
| --- | --- |
| `mimikatz` | any field contains `mimikatz` |
| `admin 10.0.0.5` | both terms appear (in any fields) |
| `"logon type"` | the exact phrase appears (inside quotes, write `""` for a literal `"`) |
| `-svchost` | `svchost` does **not** appear |
| `TargetUserName:adm` | the `TargetUserName` field contains `adm` |
| `LogonType=3` | the `LogonType` field equals `3` |
| `LogonType=network` | …or equals its decoded meaning |
| `CommandLine~"-enc\s"` | the `CommandLine` field matches a regex |
| `ScriptBlockText:` | the event has a `ScriptBlockText` field at all |
| `-IpAddress=::1` | exclude by field |

**Field names** are case-insensitive. They match either the full dotted path shown in the details pane (`Execution.ProcessID`) or just its last part (`ProcessID`). **Fields ⏷** next to the search box lists every field name in the open log, with counts; click one to start a `Field:` term.

Spaces in field names are ignored, so `NewValue:` finds Defender's `New Value` field.

**Shortcuts:** `id` = EventID, `provider` = Provider.Name, `user` = Security.UserID, `pid` = ProcessID, `tid` = ThreadID, `time` = TimeCreated.SystemTime, `recordid` = EventRecordID. `process` and `parentprocess` search both Sysmon (`Image`, `ParentImage`) and Security 4688 (`NewProcessName`, `ParentProcessName`) naming.

Search also covers the built-in descriptions and decoded values. For example, `"failed to log on"` finds 4625 events, and `"audit failure"` finds events by keyword.

A term like `C:\Windows` that isn't a known field name is searched as plain text.

### Regex mode

The whole query is one regular expression ([Rust `regex` syntax](https://docs.rs/regex/latest/regex/#syntax)). Each event is searched as a list of `Field=value` lines, so `^` and `$` match at the start and end of each field:

```text
^ServiceName=.*\$$                                       service tickets for machine accounts
^CommandLine=.*(-enc|-encodedcommand)\s                  encoded PowerShell
(iex|invoke-expression|downloadstring|frombase64string)  common download-cradle keywords
^TargetUserName=(administrator|admin)$                   exact account names
```

If the query is invalid, it turns red, the error appears under the search bar, and the last good results stay on screen.

### Hunting examples

| Goal | Query |
| --- | --- |
| Kerberoasting (RC4 service tickets) | `id=4769 TicketEncryptionType=rc4-hmac` |
| Password spraying / bad passwords | `id=4771` or `id=4625 SubStatus=0xc000006a` |
| Network logons from one host | `id=4624 LogonType=3 IpAddress=10.1.2.3` |
| RDP logons | `id=4624 LogonType=10` |
| New services | `id=7045` or `id=4697` |
| Log clearing | Event IDs `1102, 104` |
| PowerShell script blocks mentioning a keyword | `ScriptBlockText:invoke-` |
| Process creation with encoded commands | `id=4688 CommandLine~"-e(nc\|ncodedcommand)?\s"` |

## Filters

The second toolbar row filters alongside the search:

- **Event IDs:** `4624, 4625` includes, `-4634` excludes, `4720-4767` gives a range.
- **Provider:** pick from every provider in the log, with event counts.
- **From / To:** UTC time, any prefix of `YYYY-MM-DD hh:mm:ss.ffffff`. `To` is inclusive, so `2024-05-21` includes that whole day.
- **Levels:** Critical, Error, Warning, Information and Verbose checkboxes.
- **✖ Clear filters** resets everything.

Click a column header to sort; click again to reverse the order. **View → Columns** shows or hides columns. Available columns: Level, Date and Time, Record #, EventRecordID, Event ID, Description, Provider, Channel, Computer, User SID, PID, TID, Task, Opcode, Keywords and Event Data. Your column choices, search mode and theme are remembered between launches.

## Reading an event

Click a row (or use the arrow keys) to open its details below the table:

- **Details:** every field, grouped into *Event Data*, *Additional* (e.g. `RenderingInfo`) and *System*. Decoded meanings appear in green next to raw values, e.g. `0x8020000000000000 Audit Success`, `LogonType 3 Network`, `SubStatus 0xc000006a Correct user name but wrong password`, `S-1-5-18 SYSTEM`. Search matches are highlighted.
- **JSON** and **XML:** the full raw event, with a copy button.

Right-click a value to:

- **Filter** or **Exclude** `Field = value`. This adds a term to the search, so you can pivot in one click.
- **Search for this value in any field**
- **Copy** the value, or `field = value`

Right-click a table row to show only or exclude its Event ID, filter by its computer, set the time range from that event onward (or up to it), or copy the event as JSON, XML or text.

> **Record # vs EventRecordID:** *Record #* is the record's number in the file. *EventRecordID* is the event's own ID from `System` (what Windows Event Viewer shows). They're usually equal, but can differ in logs that were exported or collected by triage tools.

## Detections

When a log finishes loading, Tidewatch runs its built-in detection rules over it. The **🛡 Detections** button at the start of the second toolbar row shows how many rules matched, colored by the highest severity found.

Open it to see:

- **Show all flagged events**: every event matched by at least one rule.
- Every rule that matched, grouped by [MITRE ATT&CK](https://attack.mitre.org/) tactic, with its severity and number of hits. Tick **Show rules with no matches** to see the full library.

Pick a rule to filter the table to its matches. A banner above the table explains the rule:

- what the activity means and why it matters
- its ATT&CK technique (linked), event IDs and the exact matching logic, in the same query language as the search box
- known false positives
- the original rule's authors, and links to the sources it was adapted from

The **Detection** column and the event details also show which rules an event matched; click a rule there to see all its matches.

Rules come in two kinds:

- **Single-event rules**, e.g. *Kerberoasting*: a 4769 service ticket with RC4 encryption for a user service account.
- **Threshold rules**, e.g. *password spraying*: more than 10 different accounts failing from one IP address within 24 hours.

### Importing Sigma rules

Tidewatch can also run rules from the [Sigma](https://github.com/SigmaHQ/sigma) project, the open standard for detection rules, which has thousands of community-maintained Windows rules.

1. Download Sigma: on its GitHub page click **Code → Download ZIP** and unzip it, or run `git clone https://github.com/SigmaHQ/sigma`.
2. In Tidewatch open **🛡 Detections → Import folder…** and choose the `sigma/rules` folder (or any folder of Sigma `.yml` files, including your own rules).

Imported rules run alongside the built-in ones and are tagged *Sigma* in the list. Tidewatch remembers the folder and re-imports it on every launch; **Reload** picks up changes and **Remove** stops using it. Hover the import status to see how many files were skipped and why.

What's supported: field matching with wildcards and all common value modifiers (`contains`, `startswith`, `endswith`, `all`, `re`, `cased`, `windash`, `base64`, `base64offset`, `utf16le`/`wide`, `cidr`, `exists`, `gt`/`lt`, `fieldref`), keyword lists, and full conditions (`and`, `or`, `not`, `1 of selection_*`, `all of them`). Log sources are mapped to the matching Windows logs; for example `category: process_creation` checks both Sysmon event 1 and Security event 4688, translating field names such as `Image` → `NewProcessName`.

Skipped: rules for other platforms (Linux, macOS, cloud, web servers), log types that don't exist in Windows event logs (e.g. proxy or EDR-only categories), aggregation and correlation rules, and the `expand` placeholder modifier.

How well it works: the importer is tested against Sigma's own regression samples. On all 467 official sample logs it matches exactly where the rule's logic says it should (two samples list an expected count of 1 but contain two events that each satisfy the rule). With the full Sigma rule set imported (about 2,400 Windows rules), running every rule over 300,000 events takes about a third of a second.

Sigma rules are licensed under the [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License). When the imported folder ships that license (as the Sigma repository does), Tidewatch shows each rule's authors and the license wherever its matches are displayed.

### Built-in rules

Current library (49 rules):

| Tactic | Rules |
| --- | --- |
| Credential Access | Kerberoasting · AS-REP Roasting · password spraying (Kerberos, network logon, NTLM) · user enumeration · password guessing · logons to disabled/expired accounts · DCSync · DCSync rights granted · DPAPI backup key read · LSASS memory access |
| Defense Evasion | Security / System / other logs cleared · logs cleared from the command line · audit policy disabled (critical and other) · Defender protection off, exclusions, weakened settings, detection history deleted · Defender changes and AMSI bypass via PowerShell · firewall rules deleted, suspicious firewall rules, firewall turned off · PowerShell 2 downgrade |
| Lateral Movement | Pass-the-hash · overpass-the-hash / runas /netonly · PsExec, PAExec, RemCom and CSExec services · renamed-PsExec and Impacket named pipes · random-name services · smbexec · remote commands via WMI/DCOM/services/tasks · RDP from localhost or public IPs · SMB logons from public IPs · RDP through ngrok · remote task and service pipes · ADMIN$ access · files written to C$ · explicit credentials from shells · logons through WMI |
| Antivirus | Microsoft Defender malware detections |

Many rules need specific logging to be enabled on the Windows machine, for example process creation auditing with command lines (4688) or Sysmon. On logs without those events, the matching rules simply show no hits.

Each rule is tested against events that should and shouldn't match, and the whole library is checked against Sigma's official sample logs.

## Log Summary

**View → Log Summary** opens an overview of the log:

- **File:** path, size, EVTX format version, chunk count, next record ID, and whether the log is *dirty* (not cleanly closed) or *full*
- First and last event times, and event counts per level
- **Computers**, **Channels** and **Providers**, with counts
- **Event IDs** by frequency, with descriptions
- **Target accounts** (`TargetUserName`) and **source addresses** (`IpAddress`), when present

Click any entry to filter by it.

## Export

**File → Export filtered as CSV…** or **JSON Lines…** saves exactly the events currently shown, in the current sort order.

- **CSV:** the main columns, plus all event data as `Field=value` lines in one cell.
- **JSON Lines:** one full event per line, as `{"Event": {...}}`.

## Keyboard shortcuts

| Key | Action |
| --- | --- |
| ⌘O | Open file |
| ⌘F | Focus search |
| Enter (in search) | Apply now, skipping the typing delay |
| ↑ / ↓ | Previous / next event |
| Page Up / Page Down | Jump 25 events |
| Home / End | First / last event |

## Performance

Measured on an Apple M4 Pro (14 cores), using real Security log events copied up to 500,000 records (434 MB of searchable text):

| Operation | Time |
| --- | --- |
| Plain text search (`admin`) | 5 ms |
| Field search (`TargetUserName:admin`) | 6 ms |
| Case-sensitive search | 7 ms |
| Regex (`^ServiceName=.*\$$`) | 24 ms |
| Re-sort by time | 10 ms |
| Memory | about 3.5 KB per event (about 1.7 GB for 500k events) |

What keeps it fast:

- **Parallel parsing.** The file is read in 64 KB chunks, and chunks are parsed in parallel across all cores. Rows appear while loading continues.
- **One precomputed search text per event.** Each event's `Field=value` lines are built once, in original and lowercase versions, so searching is a fast substring scan run in parallel.
- **Cached search results.** Results are reused and updated as you go:
  - Records that arrive during loading are checked on their own.
  - Typing more letters only re-checks the events that matched before.
  - Changing the level, ID, provider or time filters doesn't re-run the search at all.
- **Cached sort order.** Sorting is redone only when the sort column changes or new records arrive.
- **Short typing delay on big logs.** On logs over 50k events, the search waits a few dozen milliseconds after you stop typing, so it doesn't re-scan on every keystroke.
- **Raw JSON/XML read on demand.** It's re-read from the file only for the event you're viewing or exporting, instead of keeping a copy of every event in memory.

## How it works

```text
src/
├── main.rs     window setup
├── macos.rs    Finder integration (double-click / Open With / Dock drops)
├── loader.rs   EVTX header parsing, parallel chunk parsing, on-demand JSON/XML rendering
├── model.rs    Record: flattened fields, column lookups, search text, field-name table
├── known.rs    event descriptions and value decoders (logon types, SIDs, status codes, …)
├── search.rs   query language, matching, highlighting, narrowing detection
├── detect.rs   detection engine: single-event and threshold rules
├── rules.rs    the built-in detection rule library
├── sigma.rs    Sigma rule importer: YAML parsing, modifiers, conditions, logsource mapping
└── app.rs      UI (egui): toolbar, table, details, summary, filtering, export
```

`bundle-macos.sh` packages the app (icon, `.evtx` file association, signing, `.dmg`); `scripts/make-icon.sh` regenerates `assets/AppIcon.icns`.

Built with [`evtx`](https://github.com/omerbenamram/evtx) for parsing, [`egui`/`eframe`](https://github.com/emilk/egui) for the UI, [`rayon`](https://github.com/rayon-rs/rayon) for parallelism, and [`regex`](https://github.com/rust-lang/regex) + [`memchr`](https://github.com/BurntSushi/memchr) for searching.

## Limitations

- **No Windows message text.** Windows builds full messages (e.g. *"An account was successfully logged on…"*) from resource DLLs that only exist on a Windows install. This viewer shows the structured event data instead, plus built-in short descriptions for about 250 common event IDs (Security, System, Sysmon, PowerShell, Task Scheduler, RDP, Defender, Firewall and others).
- **Not notarized by Apple.** The one-command installer avoids the first-launch warning; the disk image needs a one-time approval (see [Install](#install)).
- **One file at a time.** Merging several logs into one timeline isn't supported yet.
- **Times are shown in UTC**, as stored in the log.
- **The original file must stay in place** while it's open, because JSON, XML and JSON Lines export are re-read from it.

## Development

```bash
cargo test                       # unit tests
cargo clippy --all-targets
cargo fmt
```

Some tests run against a real log when you point them at one:

```bash
# Cross-check the parser against the evtx crate and run end-to-end tests on a real file
EVTX_SAMPLE=path/to/Security.evtx cargo test --release -- --nocapture

# Try queries against a file (prefix a query with re: for regex mode; separate queries with ;;)
EVTX_SAMPLE=path/to/Security.evtx EVTX_QUERY='id=4624;;LogonType=3;;re:^TargetUserName=adm' \
  cargo test --release sample_queries -- --nocapture

# Scale benchmark (copies the file's records up to EVTX_N events)
EVTX_SAMPLE=path/to/Security.evtx EVTX_N=500000 cargo test --release bench_scale -- --ignored --nocapture
```

More test runs:

```bash
# Run the loader and every detection rule over all .evtx files in a folder; fails if parsing ever panics
EVTX_DIR=path/to/evtx-samples cargo test --release corpus -- --ignored --nocapture

# Check the Sigma importer against Sigma's regression samples (point SIGMA_DIR at a Sigma checkout)
SIGMA_DIR=path/to/sigma cargo test --release sigma_regression -- --ignored --nocapture

# Time every built-in and imported rule over a large log
SIGMA_DIR=path/to/sigma/rules EVTX_SAMPLE=path/to/Security.evtx EVTX_N=300000 cargo test --release sigma_scale -- --ignored --nocapture

# Corrupt a real file's chunks in hundreds of ways and check the parser never takes the app down
EVTX_SAMPLE=path/to/Security.evtx cargo test --release fuzz -- --ignored --nocapture
```

Event descriptions and value decoders live in [`src/known.rs`](src/known.rs). To add an event, append a `(provider, event_id, description)` row to `DESCRIPTIONS`.

**Adding a detection rule:** add a `Rule` to [`src/rules.rs`](src/rules.rs) with its conditions in the query language, then add tests with events that should and shouldn't match. If the rule is adapted from a Sigma or Hayabusa rule, set `author` to the original rule's authors and link the original under `references`. The Detection Rule License requires this, and a test enforces it.

## Releasing

Releases are built by GitHub Actions ([`.github/workflows/release.yml`](.github/workflows/release.yml)). Nobody needs a local build:

1. Bump `version` in `Cargo.toml` and commit.
2. Tag and push: `git tag v0.1.0 && git push origin v0.1.0`

The workflow builds the universal app, packages `Tidewatch-<version>.dmg`, and attaches it to a new GitHub Release with generated notes. It refuses to run if the tag doesn't match the `Cargo.toml` version. Every push and pull request also runs formatting, clippy and tests ([`ci.yml`](.github/workflows/ci.yml)).

**Removing the first-launch warning.** Add these repository secrets, and the workflow signs the app with your Developer ID and notarizes the `.dmg`. This needs an [Apple Developer Program](https://developer.apple.com/programs/) membership.

| Secret | Value |
| --- | --- |
| `MACOS_CERTIFICATE` | base64 of your *Developer ID Application* certificate exported as `.p12` (`base64 -i cert.p12 \| pbcopy`) |
| `MACOS_CERTIFICATE_PASSWORD` | the `.p12` export password |
| `MACOS_SIGN_IDENTITY` | e.g. `Developer ID Application: Jane Doe (AB12CD34EF)` |
| `APPLE_ID` | your Apple ID email |
| `APPLE_TEAM_ID` | your 10-character team ID |
| `APPLE_APP_PASSWORD` | an [app-specific password](https://support.apple.com/102654) for that Apple ID |

## License

Tidewatch is licensed under the [PolyForm Small Business License 1.0.0](LICENSE.md).

- **Free** for use that benefits a company with fewer than 100 people (employees and contractors) and less than US$1,000,000 (2019, inflation-adjusted) revenue in the prior tax year.
- **Larger organizations** need a commercial license. To ask about one, start a thread in [GitHub Discussions](https://github.com/Nyanites/tidewatch/discussions).

The built-in detection rules are adapted from [Sigma](https://github.com/SigmaHQ/sigma) and [Hayabusa](https://github.com/Yamato-Security/hayabusa-rules) rules and remain under the [Detection Rule License 1.1](licenses/DRL-1.1.md); see [NOTICE.md](NOTICE.md). Tidewatch shows each rule's original authors wherever its matches are displayed.

### Contributing

Contributions are welcome. Because Tidewatch is also offered under commercial licenses, contributors will be asked to agree to a contributor license agreement before a pull request can be merged.

---

Tidewatch is not affiliated with Microsoft or Apple. Windows is a trademark of Microsoft Corporation; Mac and macOS are trademarks of Apple Inc.
