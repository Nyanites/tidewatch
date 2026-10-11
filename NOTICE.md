# Notices

Tidewatch is licensed under the [PolyForm Small Business License 1.0.0](LICENSE.md),
with the exception of the material below, which keeps its own license.

## Detection rules

The built-in detection rules in [`src/rules.rs`](src/rules.rs) are adapted from:

- **Sigma** — https://github.com/SigmaHQ/sigma
- **Hayabusa rules** — https://github.com/Yamato-Security/hayabusa-rules

Both are licensed under the **Detection Rule License (DRL) 1.1**
([text](licenses/DRL-1.1.md), https://github.com/SigmaHQ/Detection-Rule-License).
As the DRL requires:

- each adapted rule keeps the names of its original authors (`author` field in
  `src/rules.rs`), and Tidewatch shows them wherever the rule's matches are displayed;
- each adapted rule links to the original rule it is based on (`references` field);
- the adapted rules remain available under the DRL 1.1.

Splunk Security Content (Apache-2.0) and Elastic detection rules are cited in some rules
as references for thresholds and context; no content from them is copied.

## Third-party libraries

Tidewatch is built on open-source Rust crates, including
[evtx](https://github.com/omerbenamram/evtx),
[egui/eframe](https://github.com/emilk/egui),
[rayon](https://github.com/rayon-rs/rayon),
[regex](https://github.com/rust-lang/regex),
[memchr](https://github.com/BurntSushi/memchr),
[serde](https://github.com/serde-rs/serde),
[yaml_serde](https://github.com/yaml/yaml-serde) and
[rfd](https://github.com/PolyMeilex/rfd), each under the MIT and/or Apache-2.0 license.
The full dependency list is in `Cargo.lock`.
