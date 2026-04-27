//! Autonomous IO loop for persistent megakernel.
//!
//! This module implements Innovation I.5: host-side pump thread that
//! polls the GPU's `io_queue` for requests and services them via
//! io_uring. This removes the CPU from the dispatch critical path.

use std::collections::HashMap;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::megakernel::io::{complete_io_request, io_op, poll_io_requests};
use crate::uring::stream::{AsyncUringStream, Iovec};
use crate::PipelineError;

const IDLE_SPINS: u32 = 64;
const MIN_IDLE_PARK: Duration = Duration::from_micros(10);
const MAX_IDLE_PARK: Duration = Duration::from_millis(1);

#[derive(Default)]
struct IdleBackoff {
    polls: u32,
}

impl IdleBackoff {
    fn reset(&mut self) {
        self.polls = 0;
    }

    fn wait(&mut self, shutdown: &AtomicBool) {
        if shutdown.load(Ordering::Acquire) {
            return;
        }
        self.polls = self.polls.saturating_add(1);
        if self.polls <= IDLE_SPINS {
            thread::yield_now();
            return;
        }
        let shift = (self.polls - IDLE_SPINS).min(7);
        let park = MIN_IDLE_PARK
            .saturating_mul(1u32 << shift)
            .min(MAX_IDLE_PARK);
        thread::park_timeout(park);
    }
}

/// Host-side pump that services GPU-driven IO requests.
pub struct MegakernelIoLoop {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<Result<(), PipelineError>>>,
}

impl MegakernelIoLoop {
    /// Start a background thread that polls `io_queue_mapped` and services
    /// requests using `stream`.
    pub fn spawn(
        mut stream: AsyncUringStream<'static>,
        io_queue_mapped: &'static mut [u8],
    ) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        let handle = thread::spawn(move || {
            let mut backoff = IdleBackoff::default();
            let mut inflight_iovs: HashMap<u64, Box<[Iovec; 1]>> = HashMap::new();
            while !shutdown_clone.load(Ordering::Acquire) {
                while let Some(cqe) = stream.ring_state.peek_cqe() {
                    let res = cqe.res;
                    let slot_idx = cqe.user_data;
                    stream.ring_state.advance_cq();
                    stream.inflight = stream.inflight.saturating_sub(1);
                    inflight_iovs.remove(&slot_idx);
                    complete_io_request(io_queue_mapped, slot_idx as u32, res >= 0)?;
                    backoff.reset();
                }

                // 1. Poll GPU for new IO requests
                let requests = poll_io_requests(io_queue_mapped)?;

                if requests.is_empty() {
                    if stream.inflight() > 0 {
                        stream.flush_submissions()?;
                        stream.ring_state.enter(0, 1, 1)?;
                    } else {
                        backoff.wait(&shutdown_clone);
                    }
                    continue;
                }
                backoff.reset();

                for req in requests {
                    match req.op_type {
                        io_op::READ => unsafe {
                            let fd = req.src_handle as i32;
                            let mut iov = Box::new([Iovec {
                                iov_base: ptr::null_mut(),
                                iov_len: 0,
                            }]);
                            stream
                                .submit_read_to_gpu_at_with_user_data(
                                    fd,
                                    req.offset,
                                    req.byte_count,
                                    u64::from(req.dst_handle),
                                    u64::from(req.slot_idx),
                                    &mut iov[..],
                                )
                                .map_err(|e| PipelineError::Backend(e.to_string()))?;
                            inflight_iovs.insert(u64::from(req.slot_idx), iov);
                        },
                        io_op::FENCE => complete_io_request(io_queue_mapped, req.slot_idx, true)?,
                        io_op::WRITE => complete_io_request(io_queue_mapped, req.slot_idx, false)?,
                        _ => complete_io_request(io_queue_mapped, req.slot_idx, false)?,
                    }
                }
                stream.flush_submissions()?;
            }
            Ok(())
        });

        Self {
            shutdown,
            handle: Some(handle),
        }
    }

    /// Stop the pump thread.
    pub fn stop(&mut self) -> Result<(), PipelineError> {
        self.shutdown.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            handle.thread().unpark();
            handle
                .join()
                .map_err(|_| PipelineError::Backend("IO loop thread panicked".to_string()))?
        } else {
            Ok(())
        }
    }
}
