//! Differential megakernel replay log.
//!
//! Every slot the host publishes into the megakernel ring is also
//! appended to a circular log on disk. A later replay run can feed
//! the log into a fresh megakernel + backend pair and diff the
//! epoch-by-epoch observable stream against the original. This
//! catches schedule-dependent bugs — GPU nondeterminism, atomic
//! ordering hazards, cache-line races — that unit tests cannot hit
//! by construction.
//!
//! ## Layout
//!
//! ```text
//! header (32 bytes, aligned to 4 KiB):
//!     magic:          b"VRRL0001"        (8 bytes)   — "Vyre Ring-Replay Log"
//!     version:        u32 = 1            (4 bytes)
//!     flags:          u32 = 0            (4 bytes)
//!     capacity:       u64                (8 bytes)   — total record slots
//!     next_slot:      u64                (8 bytes)   — write cursor (mod capacity)
//! records:                                          (capacity × RECORD_BYTES)
//!     magic:          u32 = 0xDEADBEEF  (4 bytes)  — sync marker for forward scan
//!     timestamp_ns:   u64                (8 bytes)
//!     slot_idx:       u32                (4 bytes)
//!     tenant_id:      u32                (4 bytes)
//!     opcode:         u32                (4 bytes)
//!     args:           [u32; 4]           (16 bytes)
//!     epoch:          u32                (4 bytes)  — observed at publish time
//!     reserved:       u32                (4 bytes)  — future use; zero for v1
//! ```
//!
//! Record size = 52 bytes ≤ 64. Aligning to 64 by padding the reserved
//! tail keeps records cache-line aligned so a consumer can `mmap` the
//! log and read records without tearing.
//!
//! ## Rollover
//!
//! The log is a fixed-capacity ring. `next_slot = (next_slot + 1) %
//! capacity`; a replay iterates from `next_slot` through all records
//! that have a live magic word. Records that predate the first wrap
//! are overwritten in publish order.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::PipelineError;

const LOG_MAGIC: &[u8; 8] = b"VRRL0001";
const LOG_VERSION: u32 = 1;
const RECORD_MAGIC: u32 = 0xDEAD_BEEF;
const RECORD_BYTES: u64 = 64;
const HEADER_BYTES: u64 = 32;
const MAX_REPLAY_RECORDS: u64 = 1_048_576;

/// One published ring slot as captured by the replay log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordedSlot {
    /// Host wall-clock timestamp, nanoseconds since UNIX epoch.
    pub timestamp_ns: u64,
    /// Ring slot index the host published into.
    pub slot_idx: u32,
    /// Tenant id from the slot's TENANT_WORD.
    pub tenant_id: u32,
    /// Opcode from the slot's OPCODE_WORD.
    pub opcode: u32,
    /// First four argument words (the rest of the 13-word arg space
    /// lives in a packed-slot extension and is captured separately).
    pub args: [u32; 4],
    /// Megakernel EPOCH word observed at publish time. A replay run
    /// on the same backend must reach the same epoch in the same
    /// order — divergence is the load-bearing signal.
    pub epoch: u32,
}

/// Errors surfaced by the replay-log surface. Every variant carries
/// an actionable `Fix:` hint.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReplayLogError {
    /// I/O syscall on the log file failed.
    #[error("replay log {op} on `{path}` failed: {source}. Fix: check disk space + permissions.")]
    Io {
        /// Syscall name (`open`, `seek`, `read`, `write`).
        op: &'static str,
        /// Path the syscall was issued against.
        path: String,
        /// Underlying io::Error.
        #[source]
        source: std::io::Error,
    },
    /// Log header magic or version mismatch.
    #[error("replay log `{path}` header mismatch. Fix: regenerate the log; VRRL format may have changed.")]
    HeaderMismatch {
        /// Log path.
        path: String,
    },
    /// Capacity of `0` is rejected — a zero-capacity log never accepts writes.
    #[error("replay log capacity must be > 0. Fix: construct with at least one slot.")]
    ZeroCapacity,
    /// Record capacity exceeds the replay-log bound. Capping here
    /// prevents malformed log headers from forcing host OOM during
    /// replay and keeps record offsets within checked arithmetic.
    #[error("replay log capacity {count} exceeds max {max}. Fix: shard replay into smaller logs.")]
    CapacityOverflow {
        /// Requested capacity.
        count: u64,
        /// Maximum accepted capacity.
        max: u64,
    },
}

fn io_err(op: &'static str, path: &Path, source: std::io::Error) -> ReplayLogError {
    ReplayLogError::Io {
        op,
        path: path.to_string_lossy().into_owned(),
        source,
    }
}

/// Append-only circular replay log backed by a real file. Callers
/// drive `append` on every host-side `publish_slot` and `replay_all`
/// at cert-time to walk the captured slot stream.
#[derive(Debug)]
pub struct RingLog {
    file: File,
    path_repr: String,
    capacity: u64,
    next_slot: u64,
}

impl RingLog {
    /// Open a log at `path`, creating + preallocating one with
    /// `capacity` records if no file exists yet.
    ///
    /// # Errors
    ///
    /// - [`ReplayLogError::ZeroCapacity`] if `capacity == 0`.
    /// - [`ReplayLogError::CapacityOverflow`] if `capacity > u32::MAX`.
    /// - [`ReplayLogError::Io`] on any syscall failure.
    /// - [`ReplayLogError::HeaderMismatch`] when an existing file
    ///   has the wrong magic or version.
    pub fn open(path: impl AsRef<Path>, capacity: u64) -> Result<Self, ReplayLogError> {
        if capacity == 0 {
            return Err(ReplayLogError::ZeroCapacity);
        }
        validate_capacity(capacity)?;

        let path = path.as_ref();
        let existed = path.exists();
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| io_err("open", path, e))?;

        if existed {
            let mut magic = [0u8; 8];
            file.read_exact(&mut magic)
                .map_err(|e| io_err("read", path, e))?;
            if &magic != LOG_MAGIC {
                return Err(ReplayLogError::HeaderMismatch {
                    path: path.to_string_lossy().into_owned(),
                });
            }
            let mut version_bytes = [0u8; 4];
            file.read_exact(&mut version_bytes)
                .map_err(|e| io_err("read", path, e))?;
            if u32::from_le_bytes(version_bytes) != LOG_VERSION {
                return Err(ReplayLogError::HeaderMismatch {
                    path: path.to_string_lossy().into_owned(),
                });
            }
            let mut _flags = [0u8; 4];
            file.read_exact(&mut _flags)
                .map_err(|e| io_err("read", path, e))?;
            let mut cap_bytes = [0u8; 8];
            file.read_exact(&mut cap_bytes)
                .map_err(|e| io_err("read", path, e))?;
            let mut cursor_bytes = [0u8; 8];
            file.read_exact(&mut cursor_bytes)
                .map_err(|e| io_err("read", path, e))?;
            let existing_cap = u64::from_le_bytes(cap_bytes);
            validate_capacity(existing_cap)?;
            let cursor = u64::from_le_bytes(cursor_bytes);
            return Ok(Self {
                file,
                path_repr: path.to_string_lossy().into_owned(),
                capacity: existing_cap,
                next_slot: cursor % existing_cap,
            });
        }

        // Fresh log: write the header + zero the body so every record
        // magic starts at `0` (the uninitialised sentinel the replay
        // scanner treats as EMPTY).
        let total_bytes = log_file_len(capacity)?;
        file.set_len(total_bytes)
            .map_err(|e| io_err("set_len", path, e))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|e| io_err("seek", path, e))?;
        file.write_all(LOG_MAGIC)
            .map_err(|e| io_err("write", path, e))?;
        file.write_all(&LOG_VERSION.to_le_bytes())
            .map_err(|e| io_err("write", path, e))?;
        file.write_all(&0u32.to_le_bytes())
            .map_err(|e| io_err("write", path, e))?; // flags
        file.write_all(&capacity.to_le_bytes())
            .map_err(|e| io_err("write", path, e))?;
        file.write_all(&0u64.to_le_bytes())
            .map_err(|e| io_err("write", path, e))?; // cursor

        Ok(Self {
            file,
            path_repr: path.to_string_lossy().into_owned(),
            capacity,
            next_slot: 0,
        })
    }

    /// Number of record slots in the log. Records past this capacity
    /// wrap and overwrite the oldest entry.
    #[must_use]
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Current write cursor (next slot to be overwritten).
    #[must_use]
    pub fn cursor(&self) -> u64 {
        self.next_slot
    }

    /// Path representation this log was opened against.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path_repr
    }

    /// Append a record. Overwrites the oldest slot when the log
    /// wraps. The cursor is persisted to disk on every append so a
    /// crash mid-session does not desynchronise the replay.
    ///
    /// # Errors
    ///
    /// Propagates [`ReplayLogError::Io`] on any file I/O failure.
    pub fn append(&mut self, slot: RecordedSlot) -> Result<(), ReplayLogError> {
        let record_offset = HEADER_BYTES + self.next_slot * RECORD_BYTES;
        self.file
            .seek(SeekFrom::Start(record_offset))
            .map_err(|e| self.io_err("seek", e))?;

        let mut buf = [0u8; RECORD_BYTES as usize];
        buf[0..4].copy_from_slice(&RECORD_MAGIC.to_le_bytes());
        buf[4..12].copy_from_slice(&slot.timestamp_ns.to_le_bytes());
        buf[12..16].copy_from_slice(&slot.slot_idx.to_le_bytes());
        buf[16..20].copy_from_slice(&slot.tenant_id.to_le_bytes());
        buf[20..24].copy_from_slice(&slot.opcode.to_le_bytes());
        buf[24..28].copy_from_slice(&slot.args[0].to_le_bytes());
        buf[28..32].copy_from_slice(&slot.args[1].to_le_bytes());
        buf[32..36].copy_from_slice(&slot.args[2].to_le_bytes());
        buf[36..40].copy_from_slice(&slot.args[3].to_le_bytes());
        buf[40..44].copy_from_slice(&slot.epoch.to_le_bytes());
        // bytes 44..64 reserved — explicitly zeroed by the buf init.
        self.file
            .write_all(&buf)
            .map_err(|e| self.io_err("write", e))?;

        // Persist the advanced cursor. Readers that mmap the log see
        // this value and use it to know how far to scan.
        self.next_slot = (self.next_slot + 1) % self.capacity;
        self.file
            .seek(SeekFrom::Start(24)) // header cursor offset
            .map_err(|e| self.io_err("seek", e))?;
        self.file
            .write_all(&self.next_slot.to_le_bytes())
            .map_err(|e| self.io_err("write", e))?;

        Ok(())
    }

    /// Walk the log in publish order starting at the record
    /// immediately after the current cursor (oldest still-live
    /// record). Stops at the first record whose magic differs from
    /// the crate-private `RECORD_MAGIC` sentinel — meaning the log
    /// has not yet wrapped past that position — unless every record
    /// has been written.
    ///
    /// # Errors
    ///
    /// Propagates [`ReplayLogError::Io`] on read failure.
    pub fn replay_all(&mut self) -> Result<Vec<RecordedSlot>, ReplayLogError> {
        let mut out = Vec::with_capacity(self.capacity as usize);
        for step in 0..self.capacity {
            let slot_index = (self.next_slot + step) % self.capacity;
            let offset = HEADER_BYTES + slot_index * RECORD_BYTES;
            self.file
                .seek(SeekFrom::Start(offset))
                .map_err(|e| self.io_err("seek", e))?;
            let mut buf = [0u8; RECORD_BYTES as usize];
            self.file
                .read_exact(&mut buf)
                .map_err(|e| self.io_err("read", e))?;
            let magic = read_u32(&buf, 0);
            if magic == 0 {
                // Untouched record — log has not wrapped past this slot yet.
                continue;
            }
            if magic != RECORD_MAGIC {
                return Err(ReplayLogError::HeaderMismatch {
                    path: self.path_repr.clone(),
                });
            }
            out.push(RecordedSlot {
                timestamp_ns: read_u64(&buf, 4),
                slot_idx: read_u32(&buf, 12),
                tenant_id: read_u32(&buf, 16),
                opcode: read_u32(&buf, 20),
                args: [
                    read_u32(&buf, 24),
                    read_u32(&buf, 28),
                    read_u32(&buf, 32),
                    read_u32(&buf, 36),
                ],
                epoch: read_u32(&buf, 40),
            });
        }
        Ok(out)
    }

    /// Flush + sync the file to durable storage. Callers invoke this
    /// when they want the log guaranteed on disk — the hot-path
    /// `append` does not fsync per-record.
    ///
    /// # Errors
    ///
    /// Propagates [`ReplayLogError::Io`] on fsync failure.
    pub fn sync(&mut self) -> Result<(), ReplayLogError> {
        self.file.sync_all().map_err(|e| self.io_err("sync", e))?;
        Ok(())
    }

    fn io_err(&self, op: &'static str, source: std::io::Error) -> ReplayLogError {
        ReplayLogError::Io {
            op,
            path: self.path_repr.clone(),
            source,
        }
    }
}

fn validate_capacity(capacity: u64) -> Result<(), ReplayLogError> {
    if capacity == 0 {
        return Err(ReplayLogError::ZeroCapacity);
    }
    if capacity > MAX_REPLAY_RECORDS {
        return Err(ReplayLogError::CapacityOverflow {
            count: capacity,
            max: MAX_REPLAY_RECORDS,
        });
    }
    Ok(())
}

fn log_file_len(capacity: u64) -> Result<u64, ReplayLogError> {
    capacity
        .checked_mul(RECORD_BYTES)
        .and_then(|record_bytes| HEADER_BYTES.checked_add(record_bytes))
        .ok_or(ReplayLogError::CapacityOverflow {
            count: capacity,
            max: MAX_REPLAY_RECORDS,
        })
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

fn read_u64(buf: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

/// Let callers bridge ReplayLogError into the unified PipelineError
/// surface when driving the log from the megakernel pump loop.
impl From<ReplayLogError> for PipelineError {
    fn from(err: ReplayLogError) -> Self {
        PipelineError::Backend(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(slot_idx: u32, epoch: u32) -> RecordedSlot {
        RecordedSlot {
            timestamp_ns: 1_000_000 + slot_idx as u64,
            slot_idx,
            tenant_id: 0,
            opcode: 0x4000_0000 + slot_idx,
            args: [slot_idx, slot_idx * 2, slot_idx * 3, slot_idx * 4],
            epoch,
        }
    }

    #[test]
    fn open_rejects_zero_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.vrrl");
        let err = RingLog::open(&path, 0).expect_err("zero capacity must reject");
        assert!(matches!(err, ReplayLogError::ZeroCapacity));
    }

    #[test]
    fn append_and_replay_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.vrrl");
        let mut log = RingLog::open(&path, 4).expect("open fresh log");
        log.append(rec(1, 10)).unwrap();
        log.append(rec(2, 11)).unwrap();
        log.sync().unwrap();

        let replay = log.replay_all().expect("replay");
        assert_eq!(replay.len(), 2);
        assert_eq!(replay[0].slot_idx, 1);
        assert_eq!(replay[0].epoch, 10);
        assert_eq!(replay[1].slot_idx, 2);
        assert_eq!(replay[1].epoch, 11);
    }

    #[test]
    fn log_rollover_preserves_most_recent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.vrrl");
        let mut log = RingLog::open(&path, 3).expect("open");
        for i in 0..5 {
            log.append(rec(i, 100 + i)).unwrap();
        }
        let replay = log.replay_all().expect("replay");
        assert_eq!(replay.len(), 3, "capacity=3 must retain exactly 3 records");
        let slot_ids: Vec<u32> = replay.iter().map(|r| r.slot_idx).collect();
        // Publish order: 0, 1, 2, 3, 4. After 2 wraps, live records
        // are [3, 4, 2] in ring-physical order; replay starts at
        // next_slot = 2 so the visible order is [2, 3, 4].
        assert_eq!(slot_ids, vec![2, 3, 4]);
    }

    #[test]
    fn reopen_restores_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.vrrl");
        {
            let mut log = RingLog::open(&path, 4).expect("open fresh");
            log.append(rec(1, 10)).unwrap();
            log.append(rec(2, 11)).unwrap();
            log.sync().unwrap();
        }
        let mut reopened = RingLog::open(&path, 4).expect("reopen");
        assert_eq!(reopened.cursor(), 2);
        let replay = reopened.replay_all().unwrap();
        assert_eq!(replay.len(), 2);
    }

    #[test]
    fn corrupted_magic_rejected() {
        use std::io::Write as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.vrrl");
        {
            // Create a "log" file with the wrong magic.
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"XXXX0001").unwrap();
            f.write_all(&1u32.to_le_bytes()).unwrap();
            f.write_all(&0u32.to_le_bytes()).unwrap();
            f.write_all(&4u64.to_le_bytes()).unwrap();
            f.write_all(&0u64.to_le_bytes()).unwrap();
            // Ensure enough bytes for the subsequent reads in open() (headers ≥ 32 B).
            f.set_len(HEADER_BYTES + 4 * RECORD_BYTES).unwrap();
        }
        let err = RingLog::open(&path, 4).expect_err("wrong magic must reject");
        assert!(matches!(err, ReplayLogError::HeaderMismatch { .. }));
    }

    fn write_header(path: &Path, capacity: u64, cursor: u64) {
        use std::io::Write as _;

        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(LOG_MAGIC).unwrap();
        f.write_all(&LOG_VERSION.to_le_bytes()).unwrap();
        f.write_all(&0u32.to_le_bytes()).unwrap();
        f.write_all(&capacity.to_le_bytes()).unwrap();
        f.write_all(&cursor.to_le_bytes()).unwrap();
    }

    #[test]
    fn existing_log_zero_capacity_rejected_before_cursor_modulo() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.vrrl");
        write_header(&path, 0, 0);

        let err = RingLog::open(&path, 4).expect_err("header capacity=0 must reject");
        assert!(matches!(err, ReplayLogError::ZeroCapacity));
    }

    #[test]
    fn existing_log_huge_capacity_rejected_before_replay_allocation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.vrrl");
        write_header(&path, MAX_REPLAY_RECORDS + 1, 0);

        let err = RingLog::open(&path, 4).expect_err("huge header capacity must reject");
        assert!(matches!(
            err,
            ReplayLogError::CapacityOverflow {
                count,
                max: MAX_REPLAY_RECORDS
            } if count == MAX_REPLAY_RECORDS + 1
        ));
    }

    #[test]
    fn capacity_overflow_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.vrrl");
        let err = RingLog::open(&path, MAX_REPLAY_RECORDS + 1)
            .expect_err("over-size capacity must reject");
        assert!(matches!(
            err,
            ReplayLogError::CapacityOverflow {
                count,
                max: MAX_REPLAY_RECORDS
            } if count == MAX_REPLAY_RECORDS + 1
        ));
    }
}
