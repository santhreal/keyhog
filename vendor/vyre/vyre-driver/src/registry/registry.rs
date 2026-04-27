//! Process-wide dialect registry.
//!
//! # Hot-reload contract
//!
//! `DialectRegistry::global()` returns an `ArcSwap` guard over the current
//! registry snapshot. Hot reload is allowed at any point through
//! [`DialectRegistry::install`]. Race-free means the swap is an atomic
//! replacement of the process-wide `Arc<DialectRegistry>`: every reader loads
//! one complete snapshot, all currently-live lookups finish against the
//! snapshot they loaded, and new readers after the swap observe the newly
//! installed snapshot. No lookup ever observes a partially-mutated registry.

use super::interner::{intern_string, InternedOpId};
use super::lowering::ReferenceKind;
use super::op_def::OpDef;
use arc_swap::{ArcSwap, Guard};
use rustc_hash::FxHashMap;
use std::fmt;
use std::sync::{Arc, OnceLock};
use vyre_foundation::dialect_lookup::{install_dialect_lookup, Category, DialectLookup};
use vyre_foundation::extern_registry::{ExternDialect, ExternOp};

/// Lookup target for a dialect op's lowering path.
///
/// The in-tree variants (`Wgsl`, `Spirv`, `Ptx`, `MetalIr`, `ReferenceBackend`)
/// map to the typed slots on [`vyre_foundation::dialect_lookup::LoweringTable`].
/// Out-of-tree backends (CUDA runtime, photonic, CPU-SIMD, distributed,
/// WebGL-compute, …) register by stable backend id via the table's
/// `extensions` map and are looked up by `Target::Extension("backend-id")`.
///
/// The enum is `#[non_exhaustive]` so adding an in-tree variant in 0.7 does
/// not break downstream matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Target {
    /// WGSL via naga. The in-tree wgpu backend.
    Wgsl,
    /// SPIR-V via naga. The in-tree Vulkan path.
    Spirv,
    /// PTX. Reserved for a CUDA emitter.
    Ptx,
    /// Metal IR. Reserved for a Metal emitter.
    MetalIr,
    /// Portable reference backend. Always available.
    ReferenceBackend,
    /// Out-of-tree backend registered by stable id. Matches the
    /// string a consumer wrote into
    /// [`vyre_foundation::dialect_lookup::LoweringTable::with_extension`].
    ///
    /// Examples: `"cuda"`, `"webgl"`, `"photonic"`, `"x86-avx512"`,
    /// `"distributed-nccl"`.
    Extension(&'static str),
}

/// Process-wide dialect registry — lock-free dispatch, supports hot-reloading.
///
/// # Contract
///
/// Registrations land via `inventory::submit!` at link time. The global
/// singleton initially walks every `inventory::iter::<OpDefRegistration>` entry
/// and instantiates the `ArcSwap<DialectRegistry>`.
///
/// After initialization:
/// - `lookup` uses `ArcSwap::load` yielding a lock-free `Guard`.
///   It's one atomic load + one hash + one table probe. Zero locking.
/// - `get_lowering` likewise evaluates lock-free — sub-ns.
///
/// Runtime registration (hot reload, TOML loader) is actively supported by
/// this struct. Updates swap out the underlying `Arc<DialectRegistry>`, letting
/// current readers finish against the old data snapshot via epoch-based reclamation.
pub struct DialectRegistry {
    index: FrozenIndex,
}

/// Error returned when two dialect operations claim the same stable id.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DuplicateOpIdError {
    op_id: &'static str,
    first_registrant: &'static str,
    second_registrant: &'static str,
}

impl DuplicateOpIdError {
    /// Stable operation id that appeared more than once.
    #[must_use]
    pub const fn op_id(&self) -> &'static str {
        self.op_id
    }

    /// The registrant that claimed the id first.
    #[must_use]
    pub const fn first_registrant(&self) -> &'static str {
        self.first_registrant
    }

    /// The registrant that claimed the id second.
    #[must_use]
    pub const fn second_registrant(&self) -> &'static str {
        self.second_registrant
    }
}

impl fmt::Display for DuplicateOpIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "duplicate op id `{}`: first registrant `{}`, second registrant `{}`. Fix: keep one owner for this stable id and rename or remove the conflicting registration.",
            self.op_id, self.first_registrant, self.second_registrant
        )
    }
}

impl std::error::Error for DuplicateOpIdError {}

struct FrozenIndex {
    by_id: FxHashMap<InternedOpId, &'static OpDef>,
}

impl DialectRegistry {
    pub fn global() -> Guard<Arc<Self>> {
        let loader = registry_swap();
        let guard = loader.load();
        install_dialect_lookup(guard.clone());
        guard
    }

    fn from_inventory() -> Self {
        let mut defs: Vec<OpDef> = inventory::iter::<super::dialect::OpDefRegistration>()
            .map(|reg| (reg.op)())
            .collect();
        defs.extend(Self::extern_defs());
        defs.sort_by(|left, right| (left.dialect, left.id).cmp(&(right.dialect, right.id)));
        Self::validate_no_duplicates(defs.iter()).unwrap_or_else(|err| panic!("{err}"));
        Self::from_validated_defs(defs)
    }

    fn extern_defs() -> Vec<OpDef> {
        let mut dialects: Vec<&'static ExternDialect> =
            inventory::iter::<ExternDialect>().collect();
        dialects.sort_by_key(|dialect| dialect.name);

        let mut ops: Vec<&'static ExternOp> = inventory::iter::<ExternOp>().collect();
        ops.sort_by(|left, right| (left.dialect, left.op_id).cmp(&(right.dialect, right.op_id)));

        vyre_foundation::extern_registry::verify().unwrap_or_else(|errors| {
            let message = errors
                .into_iter()
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            panic!("extern dialect inventory is invalid. Fix: {message}");
        });

        let known = dialects
            .into_iter()
            .map(|dialect| dialect.name)
            .collect::<std::collections::HashSet<_>>();

        ops.into_iter()
            .filter(|op| known.contains(op.dialect))
            .map(|op| OpDef {
                id: op.op_id,
                dialect: op.dialect,
                category: Category::Extension,
                ..OpDef::default()
            })
            .collect()
    }

    fn from_validated_defs(defs: impl IntoIterator<Item = OpDef>) -> Self {
        let mut by_id: FxHashMap<InternedOpId, &'static OpDef> = FxHashMap::default();
        for def in defs {
            let interned = intern_string(def.id);
            let leaked: &'static OpDef = Box::leak(Box::new(def));
            by_id.insert(interned, leaked);
        }
        Self {
            index: FrozenIndex { by_id },
        }
    }

    #[cfg(test)]
    fn from_defs(defs: impl IntoIterator<Item = OpDef>) -> Self {
        let defs: Vec<OpDef> = defs.into_iter().collect();
        Self::validate_no_duplicates(defs.iter()).unwrap_or_else(|err| panic!("{err}"));
        Self::from_validated_defs(defs)
    }

    /// Validate that each operation definition owns a unique stable id.
    ///
    /// This runs before registry freeze so link-order collisions fail with an
    /// actionable error instead of silently replacing one operation with
    /// another in the hot-path lookup table.
    pub fn validate_no_duplicates<'a>(
        defs: impl IntoIterator<Item = &'a OpDef>,
    ) -> Result<(), DuplicateOpIdError> {
        let mut seen: FxHashMap<&'static str, &'static str> = FxHashMap::default();
        for def in defs {
            let registrant = if def.dialect.is_empty() {
                "<unknown dialect>"
            } else {
                def.dialect
            };
            if let Some(first_registrant) = seen.insert(def.id, registrant) {
                return Err(DuplicateOpIdError {
                    op_id: def.id,
                    first_registrant,
                    second_registrant: registrant,
                });
            }
        }
        Ok(())
    }

    /// Install a new process-wide dialect registry snapshot.
    ///
    /// This is the only sanctioned mutation path. TOML hot-reload should build
    /// a complete replacement registry and publish it here; callers must never
    /// mutate the frozen index in place.
    pub fn install(new: Self) {
        registry_swap().store(Arc::new(new));
    }

    pub fn intern_op(&self, name: &str) -> InternedOpId {
        intern_string(name)
    }

    /// Hot-path lookup. Lock-free `ArcSwap` dispatch.
    pub fn lookup(&self, id: InternedOpId) -> Option<&'static OpDef> {
        self.index.by_id.get(&id).copied()
    }

    pub fn get_lowering(&self, id: InternedOpId, target: Target) -> Option<ReferenceKind> {
        let def = self.index.by_id.get(&id)?;
        if target == Target::ReferenceBackend {
            return Some(def.lowerings.cpu_ref);
        }
        None
    }

    /// Iterate over all registered operators.
    pub fn iter(&self) -> impl Iterator<Item = &'static OpDef> + '_ {
        self.index.by_id.values().copied()
    }
}

impl vyre_foundation::dialect_lookup::private::Sealed for DialectRegistry {}

impl DialectLookup for DialectRegistry {
    fn provider_id(&self) -> &'static str {
        "vyre-driver::DialectRegistry"
    }

    fn intern_op(&self, name: &str) -> InternedOpId {
        DialectRegistry::intern_op(self, name)
    }

    fn lookup(&self, id: InternedOpId) -> Option<&'static OpDef> {
        DialectRegistry::lookup(self, id)
    }
}

fn registry_swap() -> &'static ArcSwap<DialectRegistry> {
    static REGISTRY: OnceLock<ArcSwap<DialectRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| ArcSwap::from_pointee(DialectRegistry::from_inventory()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Mutex, MutexGuard, OnceLock};
    use vyre_foundation::dialect_lookup::Category;

    inventory::submit! {
        ExternDialect::new(
            "vyre-libs-driver-registry-test",
            "0.6.0-test",
            "https://example.invalid/vyre-libs-driver-registry-test",
        )
    }

    inventory::submit! {
        ExternOp::new(
            "vyre-libs-driver-registry-test",
            "vyre-libs-driver-registry-test::dummy",
        )
    }

    fn registry_test_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().expect(
            "Fix: registry test lock was poisoned; inspect the earlier failing registry test.",
        )
    }

    fn test_def(id: &'static str) -> OpDef {
        OpDef {
            id,
            ..OpDef::default()
        }
    }

    #[test]
    fn from_inventory_ingests_extern_ops() {
        let _lock = registry_test_lock();
        let registry = DialectRegistry::from_inventory();
        let op_id = "vyre-libs-driver-registry-test::dummy";
        let def = registry
            .lookup(registry.intern_op(op_id))
            .expect("Fix: extern inventory bridge must register submitted ops");
        assert_eq!(def.id, op_id);
        assert_eq!(def.dialect, "vyre-libs-driver-registry-test");
        assert_eq!(def.category, Category::Extension);
    }

    #[test]
    fn concurrent_readers_see_consistent_index() {
        let _lock = registry_test_lock();
        // FrozenIndex is lock-free by construction: after init, the map is
        // immutable and every read is a plain hash probe. This test confirms
        // concurrent reads produce consistent results — not a lock-contention
        // test (there is no lock).
        use std::sync::Arc;
        use std::thread;

        DialectRegistry::install(DialectRegistry::from_inventory());
        // `DialectRegistry::global()` returns a `Guard<Arc<DialectRegistry>>`
        // from `arc-swap`; dereference once to get the owned `Arc` the
        // worker threads share.
        let reg: Arc<DialectRegistry> = DialectRegistry::global().clone();
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let r = Arc::clone(&reg);
                thread::spawn(move || {
                    for _ in 0..100 {
                        let id = r.intern_op("io.dma_from_nvme");
                        assert!(r.lookup(id).is_some());
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("Fix: worker thread panicked during concurrent-read test; inspect the panic payload for the underlying invariant violation.");
        }
    }

    #[test]
    fn hot_swap_preserves_old_snapshot_readers() {
        let _lock = registry_test_lock();
        DialectRegistry::install(DialectRegistry::from_defs([test_def("test.old")]));
        let (loaded_tx, loaded_rx) = mpsc::channel();
        let (swap_tx, swap_rx) = mpsc::channel();

        let handle = std::thread::spawn(move || {
            let guard = DialectRegistry::global();
            let old_id = guard.intern_op("test.old");
            loaded_tx
                .send(())
                .expect("Fix: parent must be alive to coordinate registry hot-swap test.");
            swap_rx
                .recv()
                .expect("Fix: parent must signal registry hot-swap completion.");
            assert!(
                guard.lookup(old_id).is_some(),
                "old guard must keep seeing the old snapshot after install()"
            );
            let new_id = guard.intern_op("test.new");
            assert!(
                guard.lookup(new_id).is_none(),
                "old guard must not see entries from a later snapshot"
            );
        });

        loaded_rx
            .recv()
            .expect("Fix: reader thread must load the old registry snapshot.");
        DialectRegistry::install(DialectRegistry::from_defs([test_def("test.new")]));
        swap_tx
            .send(())
            .expect("Fix: reader thread must be alive after registry hot-swap.");
        handle
            .join()
            .expect("Fix: reader thread panicked during hot-swap snapshot test.");
        DialectRegistry::install(DialectRegistry::from_inventory());
    }

    #[test]
    fn new_readers_after_swap_see_new_data() {
        let _lock = registry_test_lock();
        DialectRegistry::install(DialectRegistry::from_defs([test_def("test.before")]));
        DialectRegistry::install(DialectRegistry::from_defs([test_def("test.after")]));

        let handle = std::thread::spawn(move || {
            let guard = DialectRegistry::global();
            let after = guard.intern_op("test.after");
            let before = guard.intern_op("test.before");
            assert!(
                guard.lookup(after).is_some(),
                "new reader must see the registry installed before it loaded"
            );
            assert!(
                guard.lookup(before).is_none(),
                "new reader must not see the previous registry snapshot"
            );
        });

        handle
            .join()
            .expect("Fix: reader thread panicked during post-swap visibility test.");
        DialectRegistry::install(DialectRegistry::from_inventory());
    }
}
