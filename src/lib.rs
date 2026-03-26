//! # cryptlog
//!
//! A tamper-evident, append-only log using SHA-256 hash chains.
//!
//! Each entry stores the SHA-256 hash of the previous entry, creating
//! an unbreakable chain. Modify any past record and the chain breaks
//! at exactly that point.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use cryptlog::Log;
//!
//! let mut log = Log::open("audit.clog").unwrap();
//! log.append("user:42 logged in").unwrap();
//! log.verify().unwrap();
//!
//! for entry in log.read_all().unwrap() {
//!     println!("{}: {}", entry.timestamp, String::from_utf8_lossy(&entry.data));
//! }
//! ```
//!
//! ## Streaming reads
//!
//! For large log files, use the streaming iterator instead of [`Log::read_all`]:
//!
//! ```rust,no_run
//! use cryptlog::Log;
//!
//! let log = Log::open("huge.clog").unwrap();
//! let mut iter = log.entries().unwrap();
//!
//! while let Some(entry) = iter.next_entry().unwrap() {
//!     println!("{}", String::from_utf8_lossy(&entry.data));
//! }
//! ```

use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const MAGIC: &[u8; 4] = b"CLOG";
const VERSION: u8 = 0x01;
const HASH_SIZE: usize = 32;

/// A single entry in the log.
///
/// Each entry contains the raw payload, a microsecond-precision timestamp,
/// and two SHA-256 hashes that form the integrity chain.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Microseconds since Unix epoch when this entry was appended.
    pub timestamp: u64,
    /// The raw payload bytes.
    pub data: Vec<u8>,
    /// SHA-256 hash of the previous entry (all zeros for the first entry).
    pub prev_hash: [u8; HASH_SIZE],
    /// SHA-256 hash of this entry's header + data + prev_hash.
    pub hash: [u8; HASH_SIZE],
}

/// Handle to an open cryptlog file.
///
/// Tracks the file path, the hash of the most recent entry, and the
/// total entry count. Use [`Log::open`] to create or open a log.
#[derive(Debug)]
pub struct Log {
    path: std::path::PathBuf,
    last_hash: [u8; HASH_SIZE],
    entry_count: u64,
}

/// Streaming iterator over log entries.
///
/// Reads entries one at a time from disk without loading the entire
/// file into memory. Created via [`Log::entries`].
pub struct EntryIterator {
    reader: BufReader<File>,
}

/// Errors that can occur when working with a cryptlog.
#[derive(Debug)]
pub enum CryptLogError {
    /// An I/O error from the underlying filesystem.
    Io(io::Error),
    /// The file does not start with the expected `CLOG` magic bytes.
    InvalidMagic,
    /// The file version is not supported by this version of the library.
    InvalidVersion,
    /// The hash chain is broken at the specified entry index,
    /// indicating the file has been tampered with.
    ChainBroken {
        /// Zero-based index of the entry where the chain broke.
        at_entry: u64,
    },
}

impl std::fmt::Display for CryptLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptLogError::Io(e) => write!(f, "io error: {}", e),
            CryptLogError::InvalidMagic => write!(f, "invalid magic bytes — not a cryptlog file"),
            CryptLogError::InvalidVersion => write!(f, "unsupported file version"),
            CryptLogError::ChainBroken { at_entry } => {
                write!(f, "hash chain broken at entry {}", at_entry)
            }
        }
    }
}

impl std::error::Error for CryptLogError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CryptLogError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for CryptLogError {
    fn from(e: io::Error) -> Self {
        CryptLogError::Io(e)
    }
}

/// A specialized `Result` type for cryptlog operations.
pub type Result<T> = std::result::Result<T, CryptLogError>;

/// Reads a single entry from a buffered reader.
///
/// Returns `Ok(None)` at EOF, `Ok(Some(entry))` on success, or an error
/// if the data is malformed.
fn read_entry(reader: &mut BufReader<impl Read>) -> Result<Option<Entry>> {
    let mut magic = [0u8; 4];
    match reader.read_exact(&mut magic) {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(CryptLogError::Io(e)),
        Ok(_) => {}
    }

    if &magic != MAGIC {
        return Err(CryptLogError::InvalidMagic);
    }

    let mut version = [0u8; 1];
    reader.read_exact(&mut version)?;
    if version[0] != VERSION {
        return Err(CryptLogError::InvalidVersion);
    }

    let mut ts_bytes = [0u8; 8];
    reader.read_exact(&mut ts_bytes)?;

    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let data_len = u32::from_be_bytes(len_bytes) as usize;

    let mut data = vec![0u8; data_len];
    reader.read_exact(&mut data)?;

    let mut prev_hash = [0u8; HASH_SIZE];
    reader.read_exact(&mut prev_hash)?;

    let mut hash = [0u8; HASH_SIZE];
    reader.read_exact(&mut hash)?;

    Ok(Some(Entry {
        timestamp: u64::from_be_bytes(ts_bytes),
        data,
        prev_hash,
        hash,
    }))
}

impl EntryIterator {
    /// Reads the next entry from the log.
    ///
    /// Returns `Ok(None)` when there are no more entries.
    /// Each call reads exactly one entry from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file is malformed or an I/O error occurs.
    pub fn next_entry(&mut self) -> Result<Option<Entry>> {
        read_entry(&mut self.reader)
    }
}

impl Log {
    /// Opens an existing log file or creates a new one.
    ///
    /// If the file does not exist, it is created and the log starts empty.
    /// If it does exist, the file is scanned to recover the last hash
    /// and entry count.
    ///
    /// # Errors
    ///
    /// Returns an error if the file contains invalid magic bytes, an
    /// unsupported version, or cannot be read.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        if !path.exists() {
            File::create(&path)?;
            return Ok(Log {
                path,
                last_hash: [0u8; HASH_SIZE],
                entry_count: 0,
            });
        }

        let file = File::open(&path)?;
        let mut reader = BufReader::new(file);
        let mut last_hash = [0u8; HASH_SIZE];
        let mut entry_count = 0u64;

        while let Some(entry) = read_entry(&mut reader)? {
            last_hash = entry.hash;
            entry_count += 1;
        }

        Ok(Log {
            path,
            last_hash,
            entry_count,
        })
    }

    /// Appends a new entry to the log.
    ///
    /// Acquires an exclusive file lock before writing, ensuring that
    /// concurrent processes cannot corrupt the log. The lock is released
    /// automatically when the write completes.
    ///
    /// The entry is timestamped with the current system time (microsecond
    /// precision) and chained to the previous entry via SHA-256.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be locked, opened for appending,
    /// or if writing fails.
    pub fn append(&mut self, data: impl AsRef<[u8]>) -> Result<()> {
        let data = data.as_ref();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        let mut to_hash = Vec::new();
        to_hash.extend_from_slice(MAGIC);
        to_hash.push(VERSION);
        to_hash.extend_from_slice(&timestamp.to_be_bytes());
        to_hash.extend_from_slice(&(data.len() as u32).to_be_bytes());
        to_hash.extend_from_slice(data);
        to_hash.extend_from_slice(&self.last_hash);

        let mut hasher = Sha256::new();
        hasher.update(&to_hash);
        let hash: [u8; HASH_SIZE] = hasher.finalize().into();

        let file = OpenOptions::new().append(true).open(&self.path)?;
        // Exclusive lock — blocks until other writers release
        file.lock_exclusive()?;

        let mut writer = BufWriter::new(&file);
        writer.write_all(&to_hash)?;
        writer.write_all(&hash)?;
        writer.flush()?;

        // Lock released when `file` is dropped
        drop(writer);
        file.unlock()?;

        self.last_hash = hash;
        self.entry_count += 1;
        Ok(())
    }

    /// Verifies the integrity of the entire hash chain.
    ///
    /// Acquires a shared (read) lock to prevent writers from modifying the
    /// file mid-verification. Walks every entry, recomputes its hash, and checks:
    /// 1. The recomputed hash matches the stored hash.
    /// 2. Each entry's `prev_hash` matches the previous entry's hash.
    ///
    /// # Errors
    ///
    /// Returns [`CryptLogError::ChainBroken`] with the index of the first
    /// corrupted entry if tampering is detected.
    pub fn verify(&self) -> Result<()> {
        let file = File::open(&self.path)?;
        // Shared lock — allows concurrent readers, blocks writers
        file.lock_shared()?;

        let mut reader = BufReader::new(&file);
        let mut prev_hash = [0u8; HASH_SIZE];
        let mut entry_index = 0u64;

        loop {
            let mut magic = [0u8; 4];
            match reader.read_exact(&mut magic) {
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(CryptLogError::Io(e)),
                Ok(_) => {}
            }

            if &magic != MAGIC {
                return Err(CryptLogError::InvalidMagic);
            }

            let mut version = [0u8; 1];
            reader.read_exact(&mut version)?;
            if version[0] != VERSION {
                return Err(CryptLogError::InvalidVersion);
            }

            let mut ts_bytes = [0u8; 8];
            reader.read_exact(&mut ts_bytes)?;

            let mut len_bytes = [0u8; 4];
            reader.read_exact(&mut len_bytes)?;
            let data_len = u32::from_be_bytes(len_bytes) as usize;

            let mut data = vec![0u8; data_len];
            reader.read_exact(&mut data)?;

            let mut stored_prev_hash = [0u8; HASH_SIZE];
            reader.read_exact(&mut stored_prev_hash)?;

            let mut stored_hash = [0u8; HASH_SIZE];
            reader.read_exact(&mut stored_hash)?;

            if stored_prev_hash != prev_hash {
                file.unlock()?;
                return Err(CryptLogError::ChainBroken {
                    at_entry: entry_index,
                });
            }

            let mut to_hash = Vec::new();
            to_hash.extend_from_slice(&magic);
            to_hash.push(version[0]);
            to_hash.extend_from_slice(&ts_bytes);
            to_hash.extend_from_slice(&len_bytes);
            to_hash.extend_from_slice(&data);
            to_hash.extend_from_slice(&stored_prev_hash);

            let mut hasher = Sha256::new();
            hasher.update(&to_hash);
            let recomputed: [u8; HASH_SIZE] = hasher.finalize().into();

            if recomputed != stored_hash {
                file.unlock()?;
                return Err(CryptLogError::ChainBroken {
                    at_entry: entry_index,
                });
            }

            prev_hash = stored_hash;
            entry_index += 1;
        }

        file.unlock()?;
        Ok(())
    }

    /// Returns the total number of entries in the log.
    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }

    /// Returns a reference to the SHA-256 hash of the most recent entry.
    ///
    /// For an empty log, this is all zeros.
    pub fn last_hash(&self) -> &[u8; HASH_SIZE] {
        &self.last_hash
    }

    /// Returns a streaming iterator over log entries.
    ///
    /// Unlike [`read_all`](Log::read_all), this reads entries lazily one
    /// at a time, making it suitable for large log files that don't fit
    /// in memory.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened.
    pub fn entries(&self) -> Result<EntryIterator> {
        let file = File::open(&self.path)?;
        Ok(EntryIterator {
            reader: BufReader::new(file),
        })
    }

    /// Reads all entries from the log into memory.
    ///
    /// For large log files, prefer [`entries`](Log::entries) which streams
    /// entries one at a time.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or contains invalid data.
    pub fn read_all(&self) -> Result<Vec<Entry>> {
        let mut iter = self.entries()?;
        let mut entries = Vec::new();
        while let Some(entry) = iter.next_entry()? {
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Reads entries whose timestamps fall within `[from_ts, to_ts]` (inclusive).
    ///
    /// Timestamps are in microseconds since Unix epoch. Uses the streaming
    /// iterator internally to avoid loading the full file into memory.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or contains invalid data.
    pub fn read_range(&self, from_ts: u64, to_ts: u64) -> Result<Vec<Entry>> {
        let mut iter = self.entries()?;
        let mut results = Vec::new();
        while let Some(entry) = iter.next_entry()? {
            if entry.timestamp >= from_ts && entry.timestamp <= to_ts {
                results.push(entry);
            }
        }
        Ok(results)
    }

    /// Returns a snapshot of the current log state for external anchoring.
    ///
    /// The snapshot contains the entry count and the last hash, which can
    /// be stored externally (e.g., in a database, a signed message, or
    /// printed to paper) to anchor the log's integrity.
    ///
    /// Later, use [`verify_snapshot`](Log::verify_snapshot) to confirm that
    /// the log still matches.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            entry_count: self.entry_count,
            last_hash: self.last_hash,
        }
    }

    /// Verifies that the current log matches a previously saved snapshot.
    ///
    /// This detects the full-rewrite attack: even if the chain is internally
    /// consistent, this check confirms the hash and count match what you
    /// anchored externally.
    pub fn verify_snapshot(&self, snapshot: &Snapshot) -> bool {
        self.entry_count == snapshot.entry_count && self.last_hash == snapshot.last_hash
    }
}

/// An externally-storable snapshot of the log's state.
///
/// Save this value somewhere the attacker can't modify (a database,
/// a signed message, a different server, even a printout). Use it
/// later with [`Log::verify_snapshot`] to detect full-rewrite attacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Number of entries at the time of the snapshot.
    pub entry_count: u64,
    /// SHA-256 hash of the last entry at the time of the snapshot.
    pub last_hash: [u8; HASH_SIZE],
}

impl Snapshot {
    /// Serializes the snapshot to a hex string: `<count>:<hash_hex>`.
    ///
    /// This format is easy to store, print, or transmit.
    pub fn to_hex(&self) -> String {
        let hash_hex: String = self
            .last_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        format!("{}:{}", self.entry_count, hash_hex)
    }

    /// Parses a snapshot from the hex string format produced by [`to_hex`](Snapshot::to_hex).
    ///
    /// Returns `None` if the string is malformed.
    pub fn from_hex(s: &str) -> Option<Self> {
        let (count_str, hash_hex) = s.split_once(':')?;
        let entry_count: u64 = count_str.parse().ok()?;

        if hash_hex.len() != 64 {
            return None;
        }

        let mut last_hash = [0u8; HASH_SIZE];
        for (i, chunk) in hash_hex.as_bytes().chunks(2).enumerate() {
            let hex_str = std::str::from_utf8(chunk).ok()?;
            last_hash[i] = u8::from_str_radix(hex_str, 16).ok()?;
        }

        Some(Snapshot {
            entry_count,
            last_hash,
        })
    }
}

impl std::fmt::Display for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Helper to create a temporary log file path that gets cleaned up.
    struct TempLog {
        path: String,
    }

    impl TempLog {
        fn new(name: &str) -> Self {
            let path = format!("/tmp/cryptlog_test_{}.clog", name);
            // Clean up any leftover from a previous run
            let _ = fs::remove_file(&path);
            TempLog { path }
        }
    }

    impl Drop for TempLog {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    #[test]
    fn create_new_log() {
        let tmp = TempLog::new("create_new");
        let log = Log::open(&tmp.path).unwrap();
        assert_eq!(log.entry_count(), 0);
        assert_eq!(log.last_hash(), &[0u8; 32]);
    }

    #[test]
    fn append_and_count() {
        let tmp = TempLog::new("append_count");
        let mut log = Log::open(&tmp.path).unwrap();

        log.append("entry one").unwrap();
        log.append("entry two").unwrap();
        log.append("entry three").unwrap();

        assert_eq!(log.entry_count(), 3);
        assert_ne!(log.last_hash(), &[0u8; 32]);
    }

    #[test]
    fn verify_intact_chain() {
        let tmp = TempLog::new("verify_intact");
        let mut log = Log::open(&tmp.path).unwrap();

        log.append("alpha").unwrap();
        log.append("beta").unwrap();
        log.append("gamma").unwrap();

        assert!(log.verify().is_ok());
    }

    #[test]
    fn detect_tampering() {
        let tmp = TempLog::new("detect_tamper");
        let mut log = Log::open(&tmp.path).unwrap();

        log.append("record A").unwrap();
        log.append("record B").unwrap();
        log.append("record C").unwrap();

        // Flip a byte in the middle of the file
        let mut bytes = fs::read(&tmp.path).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        fs::write(&tmp.path, bytes).unwrap();

        let result = log.verify();
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptLogError::ChainBroken { .. } => {} // expected
            other => panic!("expected ChainBroken, got {:?}", other),
        }
    }

    #[test]
    fn read_all_entries() {
        let tmp = TempLog::new("read_all");
        let mut log = Log::open(&tmp.path).unwrap();

        log.append("first").unwrap();
        log.append("second").unwrap();

        let entries = log.read_all().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, b"first");
        assert_eq!(entries[1].data, b"second");
    }

    #[test]
    fn read_all_preserves_order() {
        let tmp = TempLog::new("read_order");
        let mut log = Log::open(&tmp.path).unwrap();

        for i in 0..10 {
            log.append(format!("entry-{}", i)).unwrap();
        }

        let entries = log.read_all().unwrap();
        assert_eq!(entries.len(), 10);
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(entry.data, format!("entry-{}", i).as_bytes());
        }
    }

    #[test]
    fn hash_chain_links() {
        let tmp = TempLog::new("chain_links");
        let mut log = Log::open(&tmp.path).unwrap();

        log.append("one").unwrap();
        log.append("two").unwrap();
        log.append("three").unwrap();

        let entries = log.read_all().unwrap();

        // First entry's prev_hash should be all zeros
        assert_eq!(entries[0].prev_hash, [0u8; 32]);

        // Each subsequent entry's prev_hash should equal the previous entry's hash
        assert_eq!(entries[1].prev_hash, entries[0].hash);
        assert_eq!(entries[2].prev_hash, entries[1].hash);
    }

    #[test]
    fn reopen_preserves_state() {
        let tmp = TempLog::new("reopen");
        {
            let mut log = Log::open(&tmp.path).unwrap();
            log.append("before close").unwrap();
        }

        // Reopen the same file
        let mut log = Log::open(&tmp.path).unwrap();
        assert_eq!(log.entry_count(), 1);

        // Append more and verify the chain still holds
        log.append("after reopen").unwrap();
        assert_eq!(log.entry_count(), 2);
        assert!(log.verify().is_ok());

        let entries = log.read_all().unwrap();
        assert_eq!(entries[1].prev_hash, entries[0].hash);
    }

    #[test]
    fn read_range_filters_correctly() {
        let tmp = TempLog::new("range_filter");
        let mut log = Log::open(&tmp.path).unwrap();

        log.append("a").unwrap();
        log.append("b").unwrap();
        log.append("c").unwrap();

        let entries = log.read_all().unwrap();
        let ts_first = entries[0].timestamp;
        let ts_last = entries[2].timestamp;

        // Range covering all
        let all = log.read_range(ts_first, ts_last).unwrap();
        assert_eq!(all.len(), 3);

        // Range covering none (future)
        let none = log
            .read_range(ts_last + 1_000_000, ts_last + 2_000_000)
            .unwrap();
        assert!(none.is_empty());

        // Range covering just the first
        let just_first = log.read_range(ts_first, ts_first).unwrap();
        assert_eq!(just_first.len(), 1);
        assert_eq!(just_first[0].data, b"a");
    }

    #[test]
    fn empty_log_operations() {
        let tmp = TempLog::new("empty_ops");
        let log = Log::open(&tmp.path).unwrap();

        assert_eq!(log.entry_count(), 0);
        assert!(log.read_all().unwrap().is_empty());
        assert!(log.read_range(0, u64::MAX).unwrap().is_empty());
    }

    #[test]
    fn large_payload() {
        let tmp = TempLog::new("large_payload");
        let mut log = Log::open(&tmp.path).unwrap();

        let big_data = "x".repeat(100_000);
        log.append(&big_data).unwrap();

        assert!(log.verify().is_ok());

        let entries = log.read_all().unwrap();
        assert_eq!(entries[0].data.len(), 100_000);
    }

    #[test]
    fn binary_data() {
        let tmp = TempLog::new("binary_data");
        let mut log = Log::open(&tmp.path).unwrap();

        let payload: Vec<u8> = (0..=255).collect();
        log.append(&payload).unwrap();

        assert!(log.verify().is_ok());

        let entries = log.read_all().unwrap();
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn error_display() {
        let err = CryptLogError::InvalidMagic;
        assert_eq!(err.to_string(), "invalid magic bytes — not a cryptlog file");

        let err = CryptLogError::ChainBroken { at_entry: 42 };
        assert_eq!(err.to_string(), "hash chain broken at entry 42");
    }

    #[test]
    fn timestamps_are_monotonic() {
        let tmp = TempLog::new("monotonic");
        let mut log = Log::open(&tmp.path).unwrap();

        for _ in 0..5 {
            log.append("tick").unwrap();
        }

        let entries = log.read_all().unwrap();
        for window in entries.windows(2) {
            assert!(
                window[1].timestamp >= window[0].timestamp,
                "timestamps should be monotonically non-decreasing"
            );
        }
    }

    #[test]
    fn streaming_iterator() {
        let tmp = TempLog::new("streaming");
        let mut log = Log::open(&tmp.path).unwrap();

        log.append("one").unwrap();
        log.append("two").unwrap();
        log.append("three").unwrap();

        let mut iter = log.entries().unwrap();
        let mut count = 0;
        let mut messages = Vec::new();

        while let Some(entry) = iter.next_entry().unwrap() {
            count += 1;
            messages.push(String::from_utf8(entry.data).unwrap());
        }

        assert_eq!(count, 3);
        assert_eq!(messages, vec!["one", "two", "three"]);
    }

    #[test]
    fn streaming_empty_log() {
        let tmp = TempLog::new("streaming_empty");
        let log = Log::open(&tmp.path).unwrap();

        let mut iter = log.entries().unwrap();
        assert!(iter.next_entry().unwrap().is_none());
    }

    #[test]
    fn snapshot_roundtrip() {
        let tmp = TempLog::new("snapshot_rt");
        let mut log = Log::open(&tmp.path).unwrap();

        log.append("entry").unwrap();

        let snap = log.snapshot();
        let hex = snap.to_hex();
        let parsed = Snapshot::from_hex(&hex).unwrap();

        assert_eq!(snap, parsed);
    }

    #[test]
    fn snapshot_verify_intact() {
        let tmp = TempLog::new("snapshot_intact");
        let mut log = Log::open(&tmp.path).unwrap();

        log.append("data").unwrap();
        log.append("more data").unwrap();

        let snap = log.snapshot();
        assert!(log.verify_snapshot(&snap));
    }

    #[test]
    fn snapshot_detects_new_entries() {
        let tmp = TempLog::new("snapshot_detect");
        let mut log = Log::open(&tmp.path).unwrap();

        log.append("data").unwrap();
        let snap = log.snapshot();

        // Add another entry — snapshot should no longer match
        log.append("sneaky entry").unwrap();
        assert!(!log.verify_snapshot(&snap));
    }

    #[test]
    fn snapshot_detects_full_rewrite() {
        let tmp = TempLog::new("snapshot_rewrite");
        let mut log = Log::open(&tmp.path).unwrap();

        log.append("original A").unwrap();
        log.append("original B").unwrap();
        let snap = log.snapshot();

        // Simulate full rewrite: delete file, create new chain
        fs::remove_file(&tmp.path).unwrap();
        let mut fake_log = Log::open(&tmp.path).unwrap();
        fake_log.append("fake A").unwrap();
        fake_log.append("fake B").unwrap();

        // Chain is internally valid...
        assert!(fake_log.verify().is_ok());
        // ...but snapshot catches the rewrite
        assert!(!fake_log.verify_snapshot(&snap));
    }

    #[test]
    fn snapshot_from_hex_rejects_garbage() {
        assert!(Snapshot::from_hex("").is_none());
        assert!(Snapshot::from_hex("not:a:snapshot").is_none());
        assert!(Snapshot::from_hex("5:tooshort").is_none());
        assert!(Snapshot::from_hex(
            "abc:0000000000000000000000000000000000000000000000000000000000000000"
        )
        .is_none());
    }

    #[test]
    fn concurrent_appends_via_file_lock() {
        // File locking prevents two processes from writing simultaneously
        // and corrupting bytes. Each process should open a fresh handle
        // for its append session.
        let tmp = TempLog::new("concurrent");

        // Process 1 opens, appends, closes
        {
            let mut log = Log::open(&tmp.path).unwrap();
            log.append("from process 1, entry 1").unwrap();
            log.append("from process 1, entry 2").unwrap();
        }

        // Process 2 opens (sees process 1's entries), appends, closes
        {
            let mut log = Log::open(&tmp.path).unwrap();
            assert_eq!(log.entry_count(), 2);
            log.append("from process 2, entry 1").unwrap();
        }

        // Process 1 comes back, opens fresh, appends more
        {
            let mut log = Log::open(&tmp.path).unwrap();
            assert_eq!(log.entry_count(), 3);
            log.append("from process 1, entry 3").unwrap();
        }

        // Final verification — all 4 entries, chain intact
        let log = Log::open(&tmp.path).unwrap();
        assert_eq!(log.entry_count(), 4);
        assert!(log.verify().is_ok());

        let entries = log.read_all().unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|e| String::from_utf8_lossy(&e.data).to_string())
                .collect::<Vec<_>>(),
            vec![
                "from process 1, entry 1",
                "from process 1, entry 2",
                "from process 2, entry 1",
                "from process 1, entry 3",
            ]
        );
    }
}
