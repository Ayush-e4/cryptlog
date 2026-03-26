# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-26

### Added

- **Node.js / npm Support**: Published to npm via `napi-rs` bindings (`npm install cryptlog`)
- Core `Log` struct with `open`, `append`, `verify`, `read_all`, `read_range`, `entries`, `snapshot`, and `verify_snapshot` methods
- SHA-256 hash chain for tamper-evident integrity
- Binary file format with `CLOG` magic bytes, versioning, and microsecond timestamps
- CLI binary with `append`, `verify`, `tail`, `range`, `snapshot`, `check-snapshot`, `count`, and `help` commands
- Colored terminal output with `colored` crate
- Human-readable timestamps via `chrono`
- `CRYPTLOG_PATH` environment variable for custom log file paths
- `CryptLogError` with `Display` and `std::error::Error` implementations
- Exclusive file locking on `append` and shared locking on `verify` via `fs2`
- Streaming `EntryIterator` for memory-efficient reads of large log files
- `Snapshot` struct with hex serialization for external integrity anchoring
- Comprehensive test suite (22 unit tests + 2 doc-tests)
- CI pipeline via GitHub Actions (check, test, clippy, fmt)
- Demo example (`examples/demo.rs`) with tamper simulation
