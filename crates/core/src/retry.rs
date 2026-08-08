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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn io_error(kind: io::ErrorKind) -> io::Error {
        io::Error::new(kind, "test")
    }

    #[test]
    fn permission_denied_is_permanent_and_is_never_retried() {
        let attempts = Cell::new(0u32);
        let result: io::Result<()> = retry_io(RetryPolicy::DEFAULT, PathOrigin::Enumerated, || {
            attempts.set(attempts.get() + 1);
            Err(io_error(io::ErrorKind::PermissionDenied))
        });
        assert!(result.is_err());
        assert_eq!(
            attempts.get(),
            1,
            "a chmod-000 file fails identically every time; retrying it only burns the bound"
        );
    }

    #[test]
    fn absent_operator_path_is_permanent_but_a_vanished_walk_entry_retries() {
        let operator_attempts = Cell::new(0u32);
        let _: io::Result<()> =
            retry_io(RetryPolicy::DEFAULT, PathOrigin::OperatorSupplied, || {
                operator_attempts.set(operator_attempts.get() + 1);
                Err(io_error(io::ErrorKind::NotFound))
            });
        assert_eq!(
            operator_attempts.get(),
            1,
            "a typo in --path is a user error"
        );

        let walk_attempts = Cell::new(0u32);
        let _: io::Result<()> = retry_io(RetryPolicy::DEFAULT, PathOrigin::Enumerated, || {
            walk_attempts.set(walk_attempts.get() + 1);
            Err(io_error(io::ErrorKind::NotFound))
        });
        assert_eq!(
            walk_attempts.get(),
            RetryPolicy::DEFAULT.max_attempts,
            "an entry the walker already saw and that then vanished raced with a writer"
        );
    }

    #[test]
    fn an_unclassified_error_is_permanent_because_there_is_no_catch_all() {
        let attempts = Cell::new(0u32);
        let _: io::Result<()> = retry_io(RetryPolicy::DEFAULT, PathOrigin::Enumerated, || {
            attempts.set(attempts.get() + 1);
            Err(io_error(io::ErrorKind::InvalidData))
        });
        assert_eq!(
            attempts.get(),
            1,
            "making a new failure recoverable must require naming its cause"
        );
    }

    #[test]
    fn a_transient_failure_that_clears_succeeds_within_the_bound() {
        let attempts = Cell::new(0u32);
        let result = retry_io(RetryPolicy::DEFAULT, PathOrigin::Enumerated, || {
            attempts.set(attempts.get() + 1);
            if attempts.get() < 3 {
                Err(io_error(io::ErrorKind::Interrupted))
            } else {
                Ok(7u8)
            }
        });
        assert_eq!(result.expect("third attempt succeeds"), 7);
        assert_eq!(attempts.get(), 3);
    }

    #[test]
    fn attempts_are_bounded_even_when_the_cause_stays_transient() {
        let attempts = Cell::new(0u32);
        let _: io::Result<()> = retry_io(RetryPolicy::DEFAULT, PathOrigin::Enumerated, || {
            attempts.set(attempts.get() + 1);
            Err(io_error(io::ErrorKind::WouldBlock))
        });
        assert_eq!(attempts.get(), RetryPolicy::DEFAULT.max_attempts);
    }

    #[test]
    fn backoff_doubles_then_saturates_at_the_ceiling() {
        let policy = RetryPolicy::DEFAULT;
        assert_eq!(policy.backoff_for(2), Duration::from_millis(5));
        assert_eq!(policy.backoff_for(3), Duration::from_millis(10));
        assert_eq!(
            policy.backoff_for(64),
            policy.max_backoff,
            "a raised bound must not become a stall"
        );
    }

    #[test]
    fn open_enumerated_reports_metadata_of_the_inode_it_opened() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("f");
        std::fs::write(&path, b"0123456789").expect("write");
        let opened = open_enumerated(&path).expect("open");
        assert_eq!(opened.metadata.len(), 10);
        // Replacing the NAME after the open must not change what the handle
        // describes: this is the property that makes stat-then-open avoidable.
        std::fs::write(&path, b"replaced-with-a-much-longer-body").expect("replace");
        assert_eq!(
            opened.metadata.len(),
            10,
            "metadata came from the descriptor, not from a second path lookup"
        );
    }

    #[test]
    fn classification_is_origin_sensitive_only_for_absence() {
        assert_eq!(
            classify_io(
                &io_error(io::ErrorKind::Interrupted),
                PathOrigin::OperatorSupplied
            ),
            Some(RetryCause::Interrupted)
        );
        assert_eq!(
            classify_io(
                &io_error(io::ErrorKind::NotFound),
                PathOrigin::OperatorSupplied
            ),
            None
        );
        assert_eq!(
            classify_io(&io_error(io::ErrorKind::NotFound), PathOrigin::Enumerated),
            Some(RetryCause::VanishedUnderWalk)
        );
    }
}

/// Retry counting must reach the profile artifact, not just an internal
/// counter. These live in their own module because they need a profiler
/// runtime entered on the calling thread.
#[cfg(test)]
mod profile_visibility_tests {
    use super::*;
    use crate::{ContentError, FileContent, FileContentSource};
    use std::cell::Cell;

    /// Fails transiently `fail_times` times, then succeeds.
    struct FlakyContent {
        fail_times: Cell<u32>,
    }

    impl FileContentSource for FlakyContent {
        fn read_prefix(&self, _path: &str, _max_bytes: u64) -> Result<FileContent, ContentError> {
            let remaining = self.fail_times.get();
            if remaining > 0 {
                self.fail_times.set(remaining - 1);
                return Err(ContentError::TransientRead);
            }
            Ok(FileContent {
                text: String::new(),
                truncated: false,
            })
        }
    }

    struct AlwaysDenied;

    impl FileContentSource for AlwaysDenied {
        fn read_prefix(&self, _path: &str, _max_bytes: u64) -> Result<FileContent, ContentError> {
            Err(ContentError::PermanentRead)
        }
    }

    fn retries_recorded_while(body: impl FnOnce()) -> Vec<(keyhog_profile::RetryCause, u64)> {
        let runtime = keyhog_profile::Runtime::new();
        {
            let _context = runtime.enter();
            body();
        }
        runtime
            .take_session_retries()
            .into_iter()
            .map(|record| (record.cause, record.attempts))
            .collect()
    }

    #[test]
    fn a_retry_that_eventually_succeeds_is_still_counted() {
        // The case the whole visibility requirement exists for: the operation
        // worked, so nothing else in the run would ever mention it, and a
        // defect that fires constantly would stay comfortable.
        let recorded = retries_recorded_while(|| {
            let flaky = FlakyContent {
                fail_times: Cell::new(2),
            };
            let source = RetryingContentSource::new(&flaky);
            assert!(
                source.read_prefix("p", 64).is_ok(),
                "third attempt must succeed"
            );
        });
        assert_eq!(
            recorded,
            vec![(keyhog_profile::RetryCause::VanishedUnderWalk, 2)],
            "two failed attempts before success must report as two, not as one operation"
        );
    }

    #[test]
    fn a_permanent_failure_records_no_retry_at_all() {
        // The control for the test above: if this also reported retries, the
        // counter would be measuring calls rather than defects.
        let recorded = retries_recorded_while(|| {
            let source = RetryingContentSource::new(&AlwaysDenied);
            assert!(source.read_prefix("p", 64).is_err());
        });
        assert!(
            recorded.is_empty(),
            "a permission denial is not a retry; got {recorded:?}"
        );
    }

    #[test]
    fn every_attempt_is_counted_when_the_cause_never_clears() {
        let recorded = retries_recorded_while(|| {
            let flaky = FlakyContent {
                fail_times: Cell::new(u32::MAX),
            };
            let source = RetryingContentSource::new(&flaky);
            assert!(source.read_prefix("p", 64).is_err());
        });
        assert_eq!(
            recorded,
            vec![(
                keyhog_profile::RetryCause::VanishedUnderWalk,
                u64::from(RetryPolicy::DEFAULT.max_attempts - 1)
            )],
            "a bounded retry must report one attempt per try, not one per operation"
        );
    }
}
