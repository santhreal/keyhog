//! Multi-tenant megakernel multiplexing.
//!
//! A single persistent megakernel per GPU can service many producer
//! tools (warpscan, soleno, keyhog, vein, …) without each one
//! paying the dispatch-setup cost. The `tenant_id` field already
//! lives in the ring-slot protocol (`protocol::TENANT_WORD`); this
//! module owns the host-side bookkeeping that hands each producer a
//! stable id, reserves an opcode-range per producer, and gates
//! publish operations against a per-tenant mask so one producer
//! cannot accidentally drive another producer's opcodes.
//!
//! ## Tenants and opcodes
//!
//! Every tenant owns an opcode range `[base, base + cap)` where the
//! whole range sits inside the user-extension space reserved by
//! `vyre_runtime::megakernel::protocol::opcode` (≥ `0x4000_0000`).
//! When [`TenantRegistry::register`] returns a [`TenantHandle`],
//! callers publish into slot args `[rule_local_opcode, ...]` and
//! the registry maps that to `(tenant_base + rule_local_opcode)`
//! before writing into the ring. A tenant that tries to publish an
//! opcode outside its own range fails with a structured error.
//!
//! ## Draining
//!
//! Unregistering a tenant revokes future publishes but does NOT
//! revoke in-flight slots — the GPU is still going to execute any
//! slot it already CAS-claimed. Callers that need hard draining
//! drive [`TenantHandle::quiesce`] which spins on the megakernel
//! DONE_COUNT until every slot the tenant published has been
//! acknowledged.
//!
//! ## Daemon surface
//!
//! The registry is the reusable piece. A full `MegakernelDaemon`
//! (listening on a Unix socket, vending handles over RPC) is a thin
//! wrapper that we can ship alongside the runtime — the registry
//! here already handles the interesting concurrency.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::megakernel::protocol::opcode::SHUTDOWN;
use crate::megakernel::Megakernel;
use crate::PipelineError;

/// First opcode the tenant registry hands out. Sits inside the
/// user-extension range reserved by the megakernel protocol,
/// matching `surgec::compile::fuse::RULE_OPCODE_BASE` so fused
/// rule documents compose with tenant allocation without colliding
/// with built-in opcodes.
pub const TENANT_OPCODE_BASE: u32 = 0x4000_0000;

/// Upper bound on the tenant-id space. `tenant_id == TENANT_ID_MAX`
/// is reserved as an invalid / revoked sentinel.
pub const TENANT_ID_MAX: u32 = u32::MAX - 1;

/// Size of the opcode window reserved per tenant. 1 << 20 = 1 MiB
/// of opcodes — well over any realistic rule count per producer
/// while still allowing ~4094 simultaneous tenants inside the u32
/// opcode range.
pub const OPCODE_RANGE_PER_TENANT: u32 = 1 << 20;

/// Errors surfaced by the tenant registry.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TenantError {
    /// The registry ran out of tenant ids. Unregister unused tenants
    /// or raise the range per tenant.
    #[error("tenant registry exhausted after {issued} registrations. Fix: shrink OPCODE_RANGE_PER_TENANT or recycle tenants.")]
    RegistryFull {
        /// Number of tenants already issued when exhaustion hit.
        issued: u32,
    },
    /// Tried to publish an opcode outside the tenant's reserved
    /// range. Almost always a caller bug.
    #[error(
        "tenant {tenant_id} published local opcode {local_opcode}; out of range [0, {cap}). \
         Fix: caller must stay inside the opcode window returned by `register()`."
    )]
    OpcodeOutOfRange {
        /// Tenant id that tripped.
        tenant_id: u32,
        /// Local opcode the caller supplied.
        local_opcode: u32,
        /// Cap on the tenant's local opcode range.
        cap: u32,
    },
    /// Tenant was unregistered concurrently; its handle is stale.
    #[error("tenant {tenant_id} was revoked; handle is stale. Fix: acquire a fresh handle from the registry.")]
    Revoked {
        /// Tenant id that was revoked.
        tenant_id: u32,
    },
    /// Quiesce timed out with inflight slots still outstanding.
    #[error(
        "tenant {tenant_id} quiesce timed out with {outstanding} inflight slots. \
         Fix: ensure the megakernel is making progress (check DONE_COUNT) or raise the timeout."
    )]
    QuiesceTimeout {
        /// Tenant id whose quiesce tripped.
        tenant_id: u32,
        /// Number of slots still inflight at timeout.
        outstanding: u64,
    },
    /// Protocol error bubbled up from `Megakernel::publish_slot`.
    #[error("{0}")]
    Pipeline(#[from] PipelineError),
}

/// One tenant's accounting state. Lives inside an `Arc` so handles
/// stay valid after the registry borrow drops.
struct TenantState {
    id: u32,
    base_opcode: u32,
    opcode_cap: u32,
    /// Number of slots this tenant has ever published.
    published_count: AtomicU64,
    /// Number of slots the GPU has reported DONE for this tenant.
    /// Advanced by [`TenantHandle::note_drained`].
    drained_count: AtomicU64,
    /// Set to 1 on `unregister`; publishes reject afterwards.
    revoked: AtomicU32,
    /// Stable label for diagnostics (e.g., `"warpscan"`, `"keyhog"`).
    label: String,
}

/// Stable handle returned by [`TenantRegistry::register`]. Clones
/// share the same underlying state, so multiple producer threads
/// inside one tenant can publish through their own handles.
#[derive(Clone)]
pub struct TenantHandle {
    state: Arc<TenantState>,
}

impl std::fmt::Debug for TenantHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantHandle")
            .field("id", &self.state.id)
            .field("label", &self.state.label)
            .field("base_opcode", &self.state.base_opcode)
            .field(
                "published_count",
                &self.state.published_count.load(Ordering::Relaxed),
            )
            .field(
                "drained_count",
                &self.state.drained_count.load(Ordering::Relaxed),
            )
            .field(
                "revoked",
                &(self.state.revoked.load(Ordering::Acquire) != 0),
            )
            .finish()
    }
}

impl TenantHandle {
    /// Stable tenant id; maps onto the ring-slot `TENANT_WORD`.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.state.id
    }

    /// Human-readable label supplied at registration time.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.state.label
    }

    /// First opcode this tenant owns.
    #[must_use]
    pub fn base_opcode(&self) -> u32 {
        self.state.base_opcode
    }

    /// Convert a tenant-local opcode to the global opcode used in
    /// the ring slot. Caller enforces `local < opcode_cap()`.
    ///
    /// # Errors
    ///
    /// Returns [`TenantError::OpcodeOutOfRange`] when the local
    /// value is outside the reserved window.
    pub fn global_opcode(&self, local: u32) -> Result<u32, TenantError> {
        if local >= self.state.opcode_cap {
            return Err(TenantError::OpcodeOutOfRange {
                tenant_id: self.id(),
                local_opcode: local,
                cap: self.state.opcode_cap,
            });
        }
        let global = self.state.base_opcode + local;
        if let Err(e) = crate::megakernel::protocol::opcode::validate_user_opcode(global) {
            panic!("Tenant registry produced invalid global opcode: {e}");
        }
        Ok(global)
    }

    /// Publish a slot into the tenant's ring with a tenant-local
    /// opcode. Convenience wrapper that composes
    /// [`Megakernel::publish_slot`] with tenant bookkeeping.
    ///
    /// # Errors
    ///
    /// - [`TenantError::Revoked`] if the tenant was unregistered.
    /// - [`TenantError::OpcodeOutOfRange`] if `local_opcode` is
    ///   outside the tenant's window.
    /// - [`TenantError::Pipeline`] when the underlying
    ///   `publish_slot` rejects (e.g., slot still in-flight).
    pub fn publish_slot(
        &self,
        ring_bytes: &mut [u8],
        slot_idx: u32,
        local_opcode: u32,
        args: &[u32],
    ) -> Result<(), TenantError> {
        if self.state.revoked.load(Ordering::Acquire) != 0 {
            return Err(TenantError::Revoked {
                tenant_id: self.state.id,
            });
        }
        let global = self.global_opcode(local_opcode)?;
        Megakernel::publish_slot(ring_bytes, slot_idx, self.state.id, global, args)?;
        self.state.published_count.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    /// Number of slots this tenant has ever published.
    #[must_use]
    pub fn published_count(&self) -> u64 {
        self.state.published_count.load(Ordering::Relaxed)
    }

    /// Number of slots this tenant has observed drained (via
    /// [`note_drained`](Self::note_drained)).
    #[must_use]
    pub fn drained_count(&self) -> u64 {
        self.state.drained_count.load(Ordering::Relaxed)
    }

    /// Mark `count` slots as drained. The host pump that observes
    /// DONE_COUNT calls this when it sees the global counter
    /// advance past the tenant's last-published cursor.
    pub fn note_drained(&self, count: u64) {
        self.state.drained_count.fetch_add(count, Ordering::AcqRel);
    }

    /// Block-style quiesce: spin-waits (yielding) until every
    /// published slot has been drained or `max_spins` elapse.
    ///
    /// # Errors
    ///
    /// Returns [`TenantError::QuiesceTimeout`] when `max_spins`
    /// iterations pass without full drain. The outstanding count
    /// at timeout is included for diagnostics.
    pub fn quiesce(&self, max_spins: u64) -> Result<(), TenantError> {
        for _ in 0..max_spins {
            let pub_count = self.state.published_count.load(Ordering::Acquire);
            let drained = self.state.drained_count.load(Ordering::Acquire);
            if drained >= pub_count {
                return Ok(());
            }
            std::thread::yield_now();
        }
        let pub_count = self.state.published_count.load(Ordering::Acquire);
        let drained = self.state.drained_count.load(Ordering::Acquire);
        Err(TenantError::QuiesceTimeout {
            tenant_id: self.state.id,
            outstanding: pub_count.saturating_sub(drained),
        })
    }
}

/// Thread-safe tenant registry. One per megakernel instance.
#[derive(Default)]
pub struct TenantRegistry {
    inner: RwLock<TenantRegistryInner>,
}

#[derive(Default)]
struct TenantRegistryInner {
    tenants: HashMap<u32, TenantHandle>,
    /// Next tenant id to hand out. Starts at 1 so `0` can stay a
    /// "no tenant" sentinel if a producer forgets to register.
    next_id: u32,
}

impl TenantRegistry {
    /// Fresh registry with no tenants.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new tenant with the given diagnostic label.
    /// Returns a handle whose opcode range is reserved until
    /// [`unregister`](Self::unregister) is called.
    ///
    /// # Errors
    ///
    /// Returns [`TenantError::RegistryFull`] when the tenant id or
    /// opcode space is exhausted.
    pub fn register(&self, label: impl Into<String>) -> Result<TenantHandle, TenantError> {
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if inner.next_id >= TENANT_ID_MAX {
            return Err(TenantError::RegistryFull {
                issued: inner.next_id,
            });
        }
        let id = inner.next_id.max(1);
        // Opcodes occupy the range
        //   [TENANT_OPCODE_BASE + id * OPCODE_RANGE_PER_TENANT,
        //    ... + OPCODE_RANGE_PER_TENANT)
        // so tenant 1's first opcode is TENANT_OPCODE_BASE +
        // OPCODE_RANGE_PER_TENANT. Keeping `id=0` off the list is
        // intentional — "no tenant" callers never publish.
        let base_opcode = TENANT_OPCODE_BASE
            .checked_add(id.checked_mul(OPCODE_RANGE_PER_TENANT).ok_or_else(|| {
                TenantError::RegistryFull {
                    issued: inner.next_id,
                }
            })?)
            .ok_or(TenantError::RegistryFull {
                issued: inner.next_id,
            })?;
        // If the top of the tenant's range would overflow u32 or
        // land on the SHUTDOWN reserved opcode (u32::MAX) we've
        // overflowed the user window.
        if base_opcode
            .checked_add(OPCODE_RANGE_PER_TENANT)
            .is_none_or(|top| top == SHUTDOWN)
        {
            return Err(TenantError::RegistryFull {
                issued: inner.next_id,
            });
        }
        let handle = TenantHandle {
            state: Arc::new(TenantState {
                id,
                base_opcode,
                opcode_cap: OPCODE_RANGE_PER_TENANT,
                published_count: AtomicU64::new(0),
                drained_count: AtomicU64::new(0),
                revoked: AtomicU32::new(0),
                label: label.into(),
            }),
        };
        inner.tenants.insert(id, handle.clone());
        inner.next_id = id + 1;
        Ok(handle)
    }

    /// Unregister a tenant. Future publishes on the handle fail
    /// with [`TenantError::Revoked`]. In-flight slots already on
    /// the GPU still execute — the host is responsible for
    /// quiescing before unregister if it needs that guarantee.
    pub fn unregister(&self, tenant_id: u32) -> Option<TenantHandle> {
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let handle = inner.tenants.remove(&tenant_id)?;
        handle.state.revoked.store(1, Ordering::Release);
        Some(handle)
    }

    /// Snapshot of active tenants for observability / diagnostics.
    #[must_use]
    pub fn active_tenants(&self) -> Vec<TenantHandle> {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .tenants
            .values()
            .cloned()
            .collect()
    }

    /// Look up a tenant by id. Returns `None` if the id was
    /// unregistered.
    #[must_use]
    pub fn lookup(&self, tenant_id: u32) -> Option<TenantHandle> {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .tenants
            .get(&tenant_id)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_tenants_get_distinct_id_and_opcode_ranges() {
        let reg = TenantRegistry::new();
        let a = reg.register("warpscan").expect("register a");
        let b = reg.register("keyhog").expect("register b");
        assert_ne!(a.id(), b.id());
        assert!(a.base_opcode() + OPCODE_RANGE_PER_TENANT <= b.base_opcode());
        assert_eq!(a.label(), "warpscan");
        assert_eq!(b.label(), "keyhog");
    }

    #[test]
    fn global_opcode_rejects_out_of_range_local() {
        let reg = TenantRegistry::new();
        let t = reg.register("soleno").unwrap();
        let err = t
            .global_opcode(OPCODE_RANGE_PER_TENANT)
            .expect_err("oversized local opcode must reject");
        assert!(matches!(err, TenantError::OpcodeOutOfRange { .. }));

        let ok = t.global_opcode(42).expect("42 < cap");
        assert_eq!(ok, t.base_opcode() + 42);
    }

    #[test]
    fn publish_slot_writes_with_tenant_id_and_bumps_counter() {
        let reg = TenantRegistry::new();
        let t = reg.register("warpscan").unwrap();
        let mut ring = Megakernel::try_encode_empty_ring(4).unwrap();

        t.publish_slot(
            &mut ring,
            /* slot = */ 0,
            /* local = */ 7,
            &[1, 2, 3],
        )
        .expect("publish");
        assert_eq!(t.published_count(), 1);

        // Slot 0 should carry tenant=t.id(), opcode=t.base_opcode()+7.
        let tenant_off = super::super::megakernel::protocol::TENANT_WORD as usize * 4;
        let opcode_off = super::super::megakernel::protocol::OPCODE_WORD as usize * 4;
        let stored_tenant =
            u32::from_le_bytes(ring[tenant_off..tenant_off + 4].try_into().unwrap());
        let stored_opcode =
            u32::from_le_bytes(ring[opcode_off..opcode_off + 4].try_into().unwrap());
        assert_eq!(stored_tenant, t.id());
        assert_eq!(stored_opcode, t.base_opcode() + 7);
    }

    #[test]
    fn unregister_blocks_future_publishes() {
        let reg = TenantRegistry::new();
        let t = reg.register("vein").unwrap();
        let tenant_id = t.id();
        let mut ring = Megakernel::try_encode_empty_ring(2).unwrap();
        t.publish_slot(&mut ring, 0, 0, &[0, 0, 0])
            .expect("first publish ok");
        reg.unregister(tenant_id).expect("unregister");
        let err = t
            .publish_slot(&mut ring, 1, 0, &[0, 0, 0])
            .expect_err("publish after unregister must reject");
        assert!(matches!(err, TenantError::Revoked { .. }));
        assert!(reg.lookup(tenant_id).is_none());
    }

    #[test]
    fn quiesce_returns_when_drained_catches_up() {
        let reg = TenantRegistry::new();
        let t = reg.register("t1").unwrap();
        let mut ring = Megakernel::try_encode_empty_ring(2).unwrap();
        t.publish_slot(&mut ring, 0, 0, &[1, 2, 3]).unwrap();
        t.publish_slot(&mut ring, 1, 0, &[4, 5, 6]).unwrap();
        assert_eq!(t.published_count(), 2);
        t.note_drained(2);
        t.quiesce(1)
            .expect("drained == published after note_drained");
    }

    #[test]
    fn quiesce_times_out_when_drain_stalled() {
        let reg = TenantRegistry::new();
        let t = reg.register("t2").unwrap();
        let mut ring = Megakernel::try_encode_empty_ring(1).unwrap();
        t.publish_slot(&mut ring, 0, 0, &[0, 0, 0]).unwrap();
        // Never note_drained → quiesce must time out.
        let err = t.quiesce(4).expect_err("stalled quiesce must time out");
        assert!(matches!(
            err,
            TenantError::QuiesceTimeout { outstanding: 1, .. }
        ));
    }

    #[test]
    fn active_tenants_tracks_registrations() {
        let reg = TenantRegistry::new();
        let a = reg.register("a").unwrap();
        let b = reg.register("b").unwrap();
        let active: Vec<u32> = reg.active_tenants().iter().map(|t| t.id()).collect();
        assert!(active.contains(&a.id()));
        assert!(active.contains(&b.id()));
        reg.unregister(a.id());
        let after: Vec<u32> = reg.active_tenants().iter().map(|t| t.id()).collect();
        assert!(!after.contains(&a.id()));
        assert!(after.contains(&b.id()));
    }

    #[test]
    fn concurrent_registration_assigns_unique_ids() {
        use std::thread;
        let reg = Arc::new(TenantRegistry::new());
        let mut handles = Vec::new();
        for i in 0..32 {
            let reg = Arc::clone(&reg);
            handles.push(thread::spawn(move || {
                reg.register(format!("t{i}")).unwrap().id()
            }));
        }
        let ids: Vec<u32> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "concurrent ids must be unique");
    }
}
