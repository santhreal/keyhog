//! The one retry policy: bounded attempts, one backoff, one classification.
//!
//! # Why this module is small on purpose
//!
//! Retry is the SECOND choice, never the first. A failure that can be
//! prevented by design must be prevented, because a retry that fires is
//! evidence of a defect rather than a success. The trap this module is shaped
//! to avoid is "it will just retry" becoming a reason to ship a racy read, an
//! unbounded allocation, or a path that fails under ordinary conditions.
//!
//! Three deliberate properties enforce that:
//!
//! 1. **No catch-all cause.** [`classify_io`] returns `None` for anything it
//!    does not recognise, and `None` means permanent: the error is returned
//!    unchanged and the operation is not attempted again. Making a new failure
//!    recoverable therefore requires naming it, in public, in
//!    [`keyhog_profile::RetryCause`]. There is no bucket to quietly widen.
//! 2. **Every attempt is counted.** [`retry_classified`] records one
//!    [`keyhog_profile::record_retry`] per retry attempt, whether or not the
//!    retry eventually succeeded. A path that silently retries a thousand
//!    times reports a thousand, so it shows up as a defect rather than as
//!    comfort.
//! 3. **One bound, one backoff.** [`RetryPolicy::DEFAULT`] is the only policy.
//!    Callers do not get to pick a bigger number because their path is
//!    flakier; a path that needs more attempts needs a fix instead.
//!
//! # What must never be routed through here
//!
//! Cap refusals. The docker tar entry-count cap, the docker unpack budget, the
//! PDF string-parser work budget, `--max-file-size`, and the seventeen
//! configured source limits are deliberate refusals of input that is too big,
//! too many, or hostile. Retrying a hostile input turns a denial-of-service
//! defence into a denial of service. They stay one-shot refusals and are
//! reported as coverage gaps, never as transient failures.
//!
//! Equally: a permission denial, a genuinely absent operator-supplied path,
//! and a malformed URL are permanent. They fail identically on every attempt,
//! so a retry only burns the bound and delays the report.

use keyhog_profile::RetryCause;
use std::fs::{File, Metadata};
use std::io;
use std::path::Path;
use std::time::Duration;

/// Bounded attempts with exponential backoff.
///
/// There is exactly one of these in the product. Sources, the post-scan
/// access-target pass, and cloud adapters all use [`RetryPolicy::DEFAULT`]
/// rather than each inventing a loop, so the worst-case added latency of a
/// transient failure is a single reviewable number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    /// Total attempts, INCLUDING the first. `1` disables retry entirely.
    pub max_attempts: u32,
    /// Delay before the second attempt. Doubles per attempt.
    pub initial_backoff: Duration,
    /// Ceiling for the doubling, so a raised bound cannot become a stall.
    pub max_backoff: Duration,
}

impl RetryPolicy {
    /// The policy. Three attempts, 5 ms then 10 ms of backoff.
    ///
    /// Worst case a permanently-failing transient classification costs 15 ms
    /// and two extra syscalls per operation. That is deliberately too small to
    /// paper over a real defect: a walk over a tree where every file races
    /// would spend visible wall time and report a retry count per file, which
    /// is the signal we want rather than a silently-absorbed cost.
    pub const DEFAULT: Self = Self {
        max_attempts: 3,
        initial_backoff: Duration::from_millis(5),
        max_backoff: Duration::from_millis(40),
    };

    /// Backoff before the attempt numbered `next_attempt` (2 for the first
    /// retry), saturating at [`Self::max_backoff`].
    #[must_use]
    pub fn backoff_for(&self, next_attempt: u32) -> Duration {
        let doublings = next_attempt.saturating_sub(2).min(16);
        let scaled = self
            .initial_backoff
            .saturating_mul(1u32 << doublings.min(16));
        scaled.min(self.max_backoff)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Who named the path, which decides whether "not found" is a race or a fact.
///
/// This distinction is the whole reason `ENOENT` is not classified by error
/// kind alone. An operator who passes `--path /nope` gets a permanent error on
/// the first attempt, because retrying their typo three times helps nobody. A
/// file the walker already enumerated and then could not open genuinely raced
/// with another process, so it is worth one bounded retry before it becomes a
/// coverage gap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathOrigin {
    /// The operator named this path directly. Absence is a user error.
    OperatorSupplied,
    /// A walker already observed this entry. Absence is a race.
    Enumerated,
}

/// Classify an IO error, or return `None` when it is permanent.
///
/// `None` is the default for anything unrecognised. That is the safe
/// direction: an unclassified failure surfaces immediately as a real error
/// instead of being retried on a guess.
#[must_use]
pub fn classify_io(error: &io::Error, origin: PathOrigin) -> Option<RetryCause> {
    match error.kind() {
        io::ErrorKind::Interrupted => return Some(RetryCause::Interrupted),
        io::ErrorKind::WouldBlock => return Some(RetryCause::WouldBlock),
        io::ErrorKind::TimedOut
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted => return Some(RetryCause::Network),
        // A path the walker already saw and that has since gone is a race with
        // another writer. A path the operator named is simply not there.
        io::ErrorKind::NotFound if matches!(origin, PathOrigin::Enumerated) => {
            return Some(RetryCause::VanishedUnderWalk)
        }
        // PermissionDenied is PERMANENT by intent. A chmod-000 file fails
        // identically on every attempt, so retrying it burns the bound and
        // changes nothing; it belongs in the report as a coverage gap.
        _ => {}
    }
    classify_raw_os(error.raw_os_error()?, origin)
}

/// Errno cases `io::ErrorKind` does not name on stable Rust.
fn classify_raw_os(errno: i32, origin: PathOrigin) -> Option<RetryCause> {
    #[cfg(unix)]
    {
        // ESTALE: an NFS handle went stale under us, which is the networked
        // form of "vanished under walk" and recovers on a fresh lookup.
        const ESTALE: i32 = 116;
        const EBUSY: i32 = 16;
        const ETXTBSY: i32 = 26;
        match errno {
            ESTALE if matches!(origin, PathOrigin::Enumerated) => {
                return Some(RetryCause::VanishedUnderWalk)
            }
            EBUSY | ETXTBSY => return Some(RetryCause::Locked),
            _ => {}
        }
    }
    #[cfg(windows)]
    {
        // ERROR_SHARING_VIOLATION / ERROR_LOCK_VIOLATION: another process holds
        // the file open without sharing. Ordinary on Windows and short-lived.
        const ERROR_SHARING_VIOLATION: i32 = 32;
        const ERROR_LOCK_VIOLATION: i32 = 33;
        if matches!(errno, ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION) {
            return Some(RetryCause::Locked);
        }
    }
    let _ = (errno, origin); // LAW10: cfg-only unused-parameter binding on platforms without raw retry codes; no Result is discarded.
    None
}

/// Run `op` under the shared policy, retrying only what `classify` names.
///
/// Every retry attempt is counted through the profiler before it is made. The
/// error from the FINAL attempt is returned unchanged, so a caller's own
/// diagnostics keep the real errno rather than a wrapper.
pub fn retry_classified<T, E, C, F>(policy: RetryPolicy, classify: C, mut op: F) -> Result<T, E>
where
    C: Fn(&E) -> Option<RetryCause>,
    F: FnMut() -> Result<T, E>,
{
    let mut attempt = 1u32;
    loop {
        match op() {
            Ok(value) => return Ok(value),
            Err(error) => {
                if attempt >= policy.max_attempts {
                    return Err(error);
                }
                // No catch-all: an unclassified error is permanent.
                let Some(cause) = classify(&error) else {
                    return Err(error);
                };
                attempt += 1;
                keyhog_profile::record_retry(cause);
                let backoff = policy.backoff_for(attempt);
                if !backoff.is_zero() {
                    std::thread::sleep(backoff);
                }
            }
        }
    }
}

/// [`retry_classified`] specialised to [`io::Error`] and [`classify_io`].
pub fn retry_io<T, F>(policy: RetryPolicy, origin: PathOrigin, op: F) -> io::Result<T>
where
    F: FnMut() -> io::Result<T>,
{
    retry_classified(policy, |error| classify_io(error, origin), op)
}

/// A file and the metadata of the exact inode that was opened.
pub struct OpenedFile {
    /// The open handle. Every subsequent read must go through THIS, never
    /// through a second lookup of the same path.
    pub file: File,
    /// Metadata taken from the open descriptor, so it describes the inode the
    /// handle refers to rather than whatever the name resolves to now.
    pub metadata: Metadata,
}

/// Open an already-enumerated path once and take its metadata from the HANDLE.
///
/// This exists to DESIGN OUT the stat-then-open race rather than retry it.
/// Code that calls `fs::metadata(path)` to decide a size or a file kind and
/// then calls `File::open(path)` performs two independent path lookups, and
/// another process can replace the inode in between. The second lookup can
/// fail (a spurious error for a file that is perfectly readable), or worse,
/// succeed against a DIFFERENT file, so the size that was checked against a
/// cap is not the size that gets read.
///
/// `File::open` followed by `File::metadata` is one lookup plus an `fstat` on
/// the resulting descriptor. There is no window: the metadata always describes
/// the inode the handle holds open, and on Unix that inode stays readable
/// through the handle even if the name is unlinked afterwards.
///
/// The bounded retry here covers only the remaining genuine race, the entry
/// vanishing between enumeration and this single open.
pub fn open_enumerated(path: &Path) -> io::Result<OpenedFile> {
    retry_io(RetryPolicy::DEFAULT, PathOrigin::Enumerated, || {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        Ok(OpenedFile { file, metadata })
    })
}

/// Wraps a [`FileContentSource`](crate::FileContentSource) so its transient
/// arm is retried under the shared policy and its permanent arm is not.
///
/// This is the ONE place a content read is retried. The wrapped source has
/// already designed out what it can: it opens once and works from the handle,
/// so there is no check-then-use race of its own making. What is left is a
/// genuinely external race (the file removed, replaced, or locked between the
/// scan and this pass), which is the narrow case retry is for.
///
/// A permanent failure is returned on the first attempt, unchanged.
pub struct RetryingContentSource<'a> {
    inner: &'a dyn crate::FileContentSource,
    policy: RetryPolicy,
}

impl<'a> RetryingContentSource<'a> {
    /// Wrap `inner` with [`RetryPolicy::DEFAULT`].
    #[must_use]
    pub fn new(inner: &'a dyn crate::FileContentSource) -> Self {
        Self {
            inner,
            policy: RetryPolicy::DEFAULT,
        }
    }
}

impl crate::FileContentSource for RetryingContentSource<'_> {
    fn read_prefix(
        &self,
        path: &str,
        max_bytes: u64,
    ) -> Result<crate::FileContent, crate::ContentError> {
        retry_classified(
            self.policy,
            |error| match error {
                // The source already told us which arm this is; that
                // classification is its own, made where the errno was seen.
                crate::ContentError::TransientRead => Some(RetryCause::VanishedUnderWalk),
                crate::ContentError::PermanentRead | crate::ContentError::NotUtf8 => None,
            },
            || self.inner.read_prefix(path, max_bytes),
        )
    }
}
