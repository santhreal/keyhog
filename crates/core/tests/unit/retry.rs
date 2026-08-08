//! Unit tests for retry policy and IO classification in keyhog-core.

use keyhog_core::retry::{
    classify_io, open_enumerated, retry_io, PathOrigin, RetryPolicy, RetryingContentSource,
};
use keyhog_profile::RetryCause;
use std::cell::Cell;
use std::io;
use std::time::Duration;

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
    let _: io::Result<()> = retry_io(RetryPolicy::DEFAULT, PathOrigin::OperatorSupplied, || {
        operator_attempts.set(operator_attempts.get() + 1);
        Err(io_error(io::ErrorKind::NotFound))
    });
    assert_eq!(operator_attempts.get(), 1, "a typo in --path is a user error");

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
        classify_io(&io_error(io::ErrorKind::NotFound), PathOrigin::OperatorSupplied),
        None
    );
    assert_eq!(
        classify_io(&io_error(io::ErrorKind::NotFound), PathOrigin::Enumerated),
        Some(RetryCause::VanishedUnderWalk)
    );
}

struct FlakyContent {
    fail_times: Cell<u32>,
}

impl keyhog_core::FileContentSource for FlakyContent {
    fn read_prefix(
        &self,
        _path: &str,
        _max_bytes: u64,
    ) -> Result<keyhog_core::FileContent, keyhog_core::ContentError> {
        let remaining = self.fail_times.get();
        if remaining > 0 {
            self.fail_times.set(remaining - 1);
            return Err(keyhog_core::ContentError::TransientRead);
        }
        Ok(keyhog_core::FileContent {
            text: String::new(),
            truncated: false,
        })
    }
}

struct AlwaysDenied;

impl keyhog_core::FileContentSource for AlwaysDenied {
    fn read_prefix(
        &self,
        _path: &str,
        _max_bytes: u64,
    ) -> Result<keyhog_core::FileContent, keyhog_core::ContentError> {
        Err(keyhog_core::ContentError::PermanentRead)
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
    let recorded = retries_recorded_while(|| {
        let flaky = FlakyContent {
            fail_times: Cell::new(2),
        };
        let source = RetryingContentSource::new(&flaky);
        assert!(
            keyhog_core::FileContentSource::read_prefix(&source, "p", 64).is_ok(),
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
    let recorded = retries_recorded_while(|| {
        let source = RetryingContentSource::new(&AlwaysDenied);
        assert!(keyhog_core::FileContentSource::read_prefix(&source, "p", 64).is_err());
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
        assert!(keyhog_core::FileContentSource::read_prefix(&source, "p", 64).is_err());
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
