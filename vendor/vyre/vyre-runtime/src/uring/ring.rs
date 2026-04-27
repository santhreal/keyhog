//! Raw io_uring orchestrator and syscall wrappers.
//!
//! This module encapsulates every raw-pointer operation needed to
//! drive io_uring without pulling in a third-party wrapper crate.
//! Safety contracts are documented per-function; every `unsafe` block
//! has a `// SAFETY:` comment naming the invariant the caller relies
//! on.
#![allow(unsafe_code)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]
// The POD structs below mirror Linux `io_uring.h` exactly — per-field
// docstrings would just paraphrase the kernel headers. The struct-level
// doc on each type points at the canonical reference.
#![allow(missing_docs)]

use crate::PipelineError;
use core::mem;
use core::ptr;

// ---- io_uring Constants ----
const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;
const IORING_SETUP_SQPOLL: u32 = 1 << 1;
const IORING_ENTER_SQ_WAKEUP: u32 = 1 << 1;
const IORING_SQ_NEED_WAKEUP: u32 = 1 << 0;

const IORING_OFF_SQ_RING: u64 = 0;
const IORING_OFF_CQ_RING: u64 = 0x8000000;
const IORING_OFF_SQES: u64 = 0x10000000;

// io_uring_register opcodes (see linux/io_uring.h).
const IORING_REGISTER_BUFFERS: u32 = 0;
const IORING_REGISTER_FILES: u32 = 2;

/// SQE flag marking the `fd` field as a registered-file index.
pub const IOSQE_FIXED_FILE: u8 = 1 << 0;

// ---- Struct Definitions ----

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct io_sqring_offsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
    pub resv1: u32,
    pub resv2: u64,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct io_cqring_offsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub cqes: u32,
    pub flags: u32,
    pub resv1: u32,
    pub resv2: u64,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct io_uring_params {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    pub wq_fd: u32,
    pub resv: [u32; 3],
    pub sq_off: io_sqring_offsets,
    pub cq_off: io_cqring_offsets,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct io_uring_sqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub user_data_or_off: u64, // off or user_addr depending on context
    pub addr: u64,
    pub len: u32,
    pub op_flags: u32,
    pub user_data: u64,
    pub buf_index: u16,
    pub personality: u16,
    pub file_index: i32, // union split: splices_fd_in or _pad2
    pub addr3: u64,
    pub __pad2: [u64; 1],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct io_uring_cqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

/// Orchestrator for the `io_uring` ring.
///
/// Lifetime: owns an fd + three mmap'd regions (SQ ring, CQ ring,
/// SQEs array). `Drop` closes + unmaps in reverse order.
///
/// Thread-safety: `Send + Sync` is safe because every public method
/// takes `&mut self` OR uses atomic operations on the ring pointers
/// (head/tail are AtomicU32 in the mmap'd memory). The `&mut self`
/// receiver on `get_sqe` + `commit_sqe` prevents two producers from
/// racing on the submission queue; CQE reaping via `peek_cqe` also
/// takes `&mut self` for the same reason on the completion side.
pub struct IoUringState {
    ring_fd: i32,
    sq_ring_ptr: *mut libc::c_void,
    sq_ring_size: usize,
    cq_ring_ptr: *mut libc::c_void,
    cq_ring_size: usize,
    sqes_ptr: *mut libc::c_void,
    sqes_size: usize,
    params: io_uring_params,
}

// Support Send/Sync since pointers are safely wrapped.
unsafe impl Send for IoUringState {}
unsafe impl Sync for IoUringState {}

impl IoUringState {
    /// Create an `IoUringState` with `entries` SQEs, SQPOLL enabled,
    /// and a 2-second kernel-thread idle timeout.
    ///
    /// # Errors
    ///
    /// - [`PipelineError::IoUringSyscall`] if `io_uring_setup`
    ///   returns < 0. Common reasons: kernel too old (< 5.1), resource
    ///   limit exceeded, missing CAP_SYS_ADMIN for SQPOLL on older
    ///   kernels.
    /// - [`PipelineError::IoUringSyscall`] if any of the three `mmap`
    ///   calls fail.
    pub fn new(entries: u32) -> Result<Self, PipelineError> {
        // SAFETY: zero-initialising a C-ABI POD struct is always sound.
        let mut params: io_uring_params = unsafe { mem::zeroed() };

        // IORING_SETUP_SQPOLL spins a kernel-side polling thread so
        // submissions don't require a syscall. sq_thread_idle is the
        // ms before that thread sleeps; 2000 ms matches tokio-uring's
        // default.
        params.flags |= IORING_SETUP_SQPOLL;
        params.sq_thread_idle = 2000;

        // SAFETY: io_uring_setup receives a valid mutable io_uring_params pointer.
        let ring_fd = unsafe {
            libc::syscall(
                libc::SYS_io_uring_setup,
                entries,
                &mut params as *mut io_uring_params,
            )
        };

        if ring_fd < 0 {
            return Err(PipelineError::IoUringSyscall {
                syscall: "io_uring_setup",
                errno: val_to_err(),
                fix: "check kernel version (>= 5.1 required), CAP_SYS_ADMIN for SQPOLL on < 5.13, and nofile ulimit",
            });
        }

        let ring_fd = ring_fd as i32;

        let sq_ring_size =
            (params.sq_off.array + params.sq_entries * mem::size_of::<u32>() as u32) as usize;
        let cq_ring_size = (params.cq_off.cqes
            + params.cq_entries * mem::size_of::<io_uring_cqe>() as u32)
            as usize;

        let (sq_size, cq_size) = if (params.features & IORING_FEAT_SINGLE_MMAP) != 0 {
            let max_size = core::cmp::max(sq_ring_size, cq_ring_size);
            (max_size, max_size)
        } else {
            (sq_ring_size, cq_ring_size)
        };

        // SAFETY: ring_fd is live and the kernel owns the shared SQ ring mapping layout.
        let sq_ring_ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                sq_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                ring_fd,
                IORING_OFF_SQ_RING as libc::off_t,
            )
        };

        if sq_ring_ptr == libc::MAP_FAILED {
            let err = val_to_err();
            // SAFETY: ring_fd is a live fd we just received from the
            // kernel; close() on failure is the correct cleanup.
            unsafe {
                libc::close(ring_fd);
            }
            return Err(PipelineError::IoUringSyscall {
                syscall: "mmap(sq_ring)",
                errno: err,
                fix: "check /proc/sys/vm/max_map_count and process memory limits",
            });
        }

        let cq_ring_ptr = if (params.features & IORING_FEAT_SINGLE_MMAP) != 0 {
            sq_ring_ptr
        } else {
            // SAFETY: same as the SQ-ring mmap above, with
            // IORING_OFF_CQ_RING for the completion-queue region.
            let ptr = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    cq_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_POPULATE,
                    ring_fd,
                    IORING_OFF_CQ_RING as libc::off_t,
                )
            };
            if ptr == libc::MAP_FAILED {
                let err = val_to_err();
                // SAFETY: sq_ring_ptr + ring_fd are valid at this
                // point; cleanup on the failure path.
                unsafe {
                    libc::munmap(sq_ring_ptr, sq_size);
                    libc::close(ring_fd);
                }
                return Err(PipelineError::IoUringSyscall {
                    syscall: "mmap(cq_ring)",
                    errno: err,
                    fix: "check /proc/sys/vm/max_map_count and process memory limits",
                });
            }
            ptr
        };

        let sqes_size = (params.sq_entries as usize) * mem::size_of::<io_uring_sqe>();
        // SAFETY: the kernel exposes exactly sq_entries io_uring_sqe records at IORING_OFF_SQES.
        let sqes_ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                sqes_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                ring_fd,
                IORING_OFF_SQES as libc::off_t,
            )
        };

        if sqes_ptr == libc::MAP_FAILED {
            let err = val_to_err();
            // SAFETY: every resource held so far is live; unmap + close
            // on the failure path.
            unsafe {
                if (params.features & IORING_FEAT_SINGLE_MMAP) == 0 {
                    libc::munmap(cq_ring_ptr, cq_size);
                }
                libc::munmap(sq_ring_ptr, sq_size);
                libc::close(ring_fd);
            }
            return Err(PipelineError::IoUringSyscall {
                syscall: "mmap(sqes)",
                errno: err,
                fix: "check /proc/sys/vm/max_map_count and process memory limits",
            });
        }

        Ok(Self {
            ring_fd,
            sq_ring_ptr,
            sq_ring_size: sq_size,
            cq_ring_ptr,
            cq_ring_size: cq_size,
            sqes_ptr,
            sqes_size,
            params,
        })
    }

    /// Enter the ring to submit items or wait for completions.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::IoUringSyscall`] if the syscall
    /// fails. Typical causes: `EINTR` (retry), `EBUSY` (wait and
    /// retry), `ENXIO` (kernel-side SQPOLL thread died).
    pub fn enter(
        &self,
        to_submit: u32,
        min_complete: u32,
        flags: u32,
    ) -> Result<i32, PipelineError> {
        // SAFETY: ring_fd is alive for &self; SQE/CQE data is in
        // mmap'd memory the kernel shares with us.
        let res = unsafe {
            libc::syscall(
                libc::SYS_io_uring_enter,
                self.ring_fd,
                to_submit,
                min_complete,
                flags,
                ptr::null::<libc::sigset_t>(),
                0, // sigsetsize
            )
        };
        if res < 0 {
            Err(PipelineError::IoUringSyscall {
                syscall: "io_uring_enter",
                errno: val_to_err(),
                fix: "retry on EINTR/EBUSY; check SQPOLL thread health via /proc/<pid>/task/ on ENXIO",
            })
        } else {
            Ok(res as i32)
        }
    }

    /// True when this ring was created with kernel-side SQ polling.
    #[must_use]
    pub fn uses_sqpoll(&self) -> bool {
        (self.params.flags & IORING_SETUP_SQPOLL) != 0
    }

    /// True when the SQPOLL thread has slept and must be explicitly woken.
    #[must_use]
    pub fn sq_needs_wakeup(&self) -> bool {
        // SAFETY: sq_ring_ptr is a valid mmap'd SQ ring. The flags word is
        // kernel-owned and documented as an atomically observed status field.
        unsafe {
            let flags = (*(self.sq_ring_ptr.add(self.params.sq_off.flags as usize)
                as *const core::sync::atomic::AtomicU32))
                .load(core::sync::atomic::Ordering::Acquire);
            (flags & IORING_SQ_NEED_WAKEUP) != 0
        }
    }

    /// Wake a sleeping SQPOLL thread so already-published SQEs make progress.
    pub fn wake_sqpoll(&self) -> Result<i32, PipelineError> {
        self.enter(0, 0, IORING_ENTER_SQ_WAKEUP)
    }

    /// Obtain a mutable reference to the next available SQE.
    pub fn get_sqe(&mut self) -> Option<&mut io_uring_sqe> {
        // SAFETY: mmap regions and kernel offsets are valid; &mut self forbids producers racing.
        unsafe {
            let head = (*(self.sq_ring_ptr.add(self.params.sq_off.head as usize)
                as *const core::sync::atomic::AtomicU32))
                .load(core::sync::atomic::Ordering::Acquire);
            let tail_ptr = self.sq_ring_ptr.add(self.params.sq_off.tail as usize)
                as *const core::sync::atomic::AtomicU32;
            let tail = (*tail_ptr).load(core::sync::atomic::Ordering::Relaxed);
            let ring_entries = *(self
                .sq_ring_ptr
                .add(self.params.sq_off.ring_entries as usize)
                as *const u32);

            if tail.wrapping_sub(head) < ring_entries {
                let ring_mask =
                    *(self.sq_ring_ptr.add(self.params.sq_off.ring_mask as usize) as *const u32);
                let idx = tail & ring_mask;
                let sqes = self.sqes_ptr as *mut io_uring_sqe;
                Some(&mut *sqes.add(idx as usize))
            } else {
                None
            }
        }
    }

    /// Commit the currently acquired SQE and advance the SQ tail.
    pub fn commit_sqe(&mut self) {
        // SAFETY: same ring invariants as get_sqe; Release tail publish orders SQE writes.
        unsafe {
            let tail_ptr = self.sq_ring_ptr.add(self.params.sq_off.tail as usize)
                as *const core::sync::atomic::AtomicU32;
            let tail = (*tail_ptr).load(core::sync::atomic::Ordering::Relaxed);
            let array_ptr = self.sq_ring_ptr.add(self.params.sq_off.array as usize) as *mut u32;
            let ring_mask =
                *(self.sq_ring_ptr.add(self.params.sq_off.ring_mask as usize) as *const u32);
            let idx = tail & ring_mask;

            *array_ptr.add(idx as usize) = idx;
            (*(tail_ptr as *mut core::sync::atomic::AtomicU32))
                .store(tail.wrapping_add(1), core::sync::atomic::Ordering::Release);
        }
    }

    /// Read the next available CQE from the completion queue.
    pub fn peek_cqe(&mut self) -> Option<&io_uring_cqe> {
        // SAFETY: cq_ring_ptr is live and Acquire tail reads synchronize with kernel CQE writes.
        unsafe {
            let head_ptr = self.cq_ring_ptr.add(self.params.cq_off.head as usize)
                as *const core::sync::atomic::AtomicU32;
            let head = (*head_ptr).load(core::sync::atomic::Ordering::Relaxed);
            let tail = (*(self.cq_ring_ptr.add(self.params.cq_off.tail as usize)
                as *const core::sync::atomic::AtomicU32))
                .load(core::sync::atomic::Ordering::Acquire);

            if head != tail {
                let ring_mask =
                    *(self.cq_ring_ptr.add(self.params.cq_off.ring_mask as usize) as *const u32);
                let idx = head & ring_mask;
                let cqes =
                    self.cq_ring_ptr.add(self.params.cq_off.cqes as usize) as *const io_uring_cqe;
                Some(&*cqes.add(idx as usize))
            } else {
                None
            }
        }
    }

    /// Register a set of buffers with the kernel via
    /// `IORING_REGISTER_BUFFERS`, unlocking `IORING_OP_READ_FIXED`
    /// zero-validation reads. `iovecs` must outlive every SQE that
    /// references a `buf_index` into it; the kernel only reads
    /// `iovecs` during this registration call itself.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::IoUringSyscall`] if
    /// `io_uring_register` fails — typical causes are `EFAULT` (bad
    /// pointer), `ENOMEM`, or `EOPNOTSUPP` (kernel < 5.1).
    pub fn register_buffers(
        &self,
        iovecs: &[crate::uring::stream::Iovec],
    ) -> Result<(), PipelineError> {
        // SAFETY: ring fd and iovec slice are live for the duration of io_uring_register.
        let res = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.ring_fd,
                IORING_REGISTER_BUFFERS,
                iovecs.as_ptr() as *const core::ffi::c_void,
                iovecs.len() as u32,
            )
        };
        if res < 0 {
            Err(PipelineError::IoUringSyscall {
                syscall: "io_uring_register(BUFFERS)",
                errno: val_to_err(),
                fix: "check /proc/sys/vm/max_user_watches; EOPNOTSUPP means kernel < 5.1",
            })
        } else {
            Ok(())
        }
    }

    /// Register fixed files via `IORING_REGISTER_FILES`. After
    /// registration, SQEs that set [`IOSQE_FIXED_FILE`] treat `fd` as
    /// the index into this table, skipping the per-SQE fd refcount
    /// bump.
    ///
    /// # Errors
    ///
    /// Same as [`IoUringState::register_buffers`].
    pub fn register_files(&self, fds: &[i32]) -> Result<(), PipelineError> {
        // SAFETY: live ring fd + caller-owned fd slice.
        let res = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.ring_fd,
                IORING_REGISTER_FILES,
                fds.as_ptr() as *const core::ffi::c_void,
                fds.len() as u32,
            )
        };
        if res < 0 {
            Err(PipelineError::IoUringSyscall {
                syscall: "io_uring_register(FILES)",
                errno: val_to_err(),
                fix: "ensure every fd is still open; ENOMEM means lower the fd set size",
            })
        } else {
            Ok(())
        }
    }

    /// Advance the CQ head, acknowledging completion.
    pub fn advance_cq(&mut self) {
        // SAFETY: cq_ring_ptr is live and Release head store publishes our acknowledgement.
        unsafe {
            let head_ptr = self.cq_ring_ptr.add(self.params.cq_off.head as usize)
                as *mut core::sync::atomic::AtomicU32;
            let head = (*head_ptr).load(core::sync::atomic::Ordering::Relaxed);
            (*head_ptr).store(head.wrapping_add(1), core::sync::atomic::Ordering::Release);
        }
    }
}

impl Drop for IoUringState {
    fn drop(&mut self) {
        // SAFETY: all pointers were returned by the kernel and are unmapped once on drop.
        unsafe {
            libc::munmap(self.sqes_ptr, self.sqes_size);
            if self.sq_ring_ptr != self.cq_ring_ptr {
                libc::munmap(self.cq_ring_ptr, self.cq_ring_size);
            }
            libc::munmap(self.sq_ring_ptr, self.sq_ring_size);
            libc::close(self.ring_fd);
        }
    }
}

fn val_to_err() -> i32 {
    // SAFETY: __errno_location returns a thread-local pointer the
    // libc itself guarantees is always valid in the current thread.
    unsafe { *libc::__errno_location() as i32 }
}
