use crate::decode::base64::{Base64Decoder, Z85Decoder};
use crate::decode::caesar::CaesarDecoder;
use crate::decode::hex::HexDecoder;
#[cfg(feature = "decode")]
use crate::decode::javascript_static::JavaScriptStaticDecoder;
use crate::decode::json::JsonDecoder;
use crate::decode::reverse::ReverseDecoder;
use crate::decode::url::{
    HtmlNamedEntityDecoder, HtmlNumericEntityDecoder, MimeEncodedWordDecoder, OctalEscapeDecoder,
    QuotedPrintableDecoder, UnicodeEscapeDecoder, UrlDecoder,
};
use crate::decode::DecodeAdmission;
#[cfg(any(feature = "decode", test))]
use crate::decode::DecodeAdmissionSketch;
use crate::decode::Decoder;
use aho_corasick::AhoCorasick;
use parking_lot::RwLock;
#[cfg(test)]
use std::cell::RefCell;
use std::sync::Arc;

// The active decoder set is stored behind one shared `Arc<Vec<..>>`. Scanner
// construction captures this Arc in its immutable execution plan. Standalone
// compatibility helpers clone one Arc per call. Registration is copy-on-write,
// so existing scanners and in-flight compatibility calls keep their snapshot.
static DECODERS: std::sync::OnceLock<RwLock<DecoderRegistryState>> = std::sync::OnceLock::new();

struct DecoderRegistryState {
    decoders: Arc<Vec<RegisteredDecoder>>,
    compatibility_failure: Option<DecoderRegistrationError>,
}

#[derive(Clone)]
pub(crate) enum RegisteredDecoder {
    Shared(Arc<dyn Decoder>),
    Reverse,
    Caesar,
}

impl RegisteredDecoder {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Shared(decoder) => decoder.name(),
            Self::Reverse => "reverse",
            Self::Caesar => "caesar",
        }
    }

    fn version(&self) -> &'static str {
        match self {
            Self::Shared(decoder) => decoder.version(),
            Self::Reverse | Self::Caesar => "detector-policy-1",
        }
    }

    pub(super) fn admission(
        &self,
        chunk: &keyhog_core::Chunk,
        policy: &super::super::policy::CompiledDecodeTransformPolicy,
    ) -> DecodeAdmission {
        match self {
            Self::Shared(decoder) => decoder.admission(chunk),
            Self::Reverse => ReverseDecoder
                .admission_sketch_with_policy(chunk, policy)
                .admission(),
            Self::Caesar => CaesarDecoder
                .admission_sketch_with_policy(chunk, policy)
                .admission(),
        }
    }

    /// Metadata context that can change this decoder's admission result.
    ///
    /// Exact payload equality is checked separately. The explicit built-in
    /// allowlist is fail-closed: custom and newly added decoders disable
    /// cross-chunk admission reuse until their metadata dependency is reviewed.
    fn admission_context_key(&self, chunk: &keyhog_core::Chunk) -> Option<u8> {
        const JAVASCRIPT_STATIC_SOURCE: u8 = 1 << 0;
        const REVERSE_SOURCE: u8 = 1 << 1;
        const CAESAR_SOURCE: u8 = 1 << 2;
        const CAESAR_PATH_CLASS: u8 = 1 << 3;

        match self {
            Self::Shared(decoder) => match decoder.name() {
                "base64"
                | "hex"
                | "url"
                | "quoted-printable"
                | "html-named-entity"
                | "html-numeric-entity"
                | "octal-escape"
                | "mime-encoded-word"
                | "json"
                | "unicode-escape"
                | "z85" => Some(0),
                "javascript-static" => Some(
                    if chunk.metadata.source_type.contains("/javascript-static") {
                        JAVASCRIPT_STATIC_SOURCE
                    } else {
                        0
                    },
                ),
                _ => None,
            },
            Self::Reverse => Some(if chunk.metadata.source_type.contains("/reverse") {
                REVERSE_SOURCE
            } else {
                0
            }),
            Self::Caesar => {
                let mut key = 0;
                if chunk.metadata.source_type.contains("/caesar") {
                    key |= CAESAR_SOURCE;
                }
                if crate::decode::caesar::is_source_code_path(chunk.metadata.path.as_deref()) {
                    key |= CAESAR_PATH_CLASS;
                }
                Some(key)
            }
        }
    }

    #[cfg(any(feature = "decode", test))]
    fn admission_sketch(
        &self,
        chunk: &keyhog_core::Chunk,
        policy: &super::super::policy::CompiledDecodeTransformPolicy,
    ) -> DecodeAdmissionSketch {
        match self {
            Self::Shared(decoder) => decoder.admission_sketch(chunk),
            Self::Reverse => ReverseDecoder.admission_sketch_with_policy(chunk, policy),
            Self::Caesar => CaesarDecoder.admission_sketch_with_policy(chunk, policy),
        }
    }

    pub(super) fn decode_chunk_into(
        &self,
        chunk: &keyhog_core::Chunk,
        policy: &super::super::policy::CompiledDecodeTransformPolicy,
        sink: &mut dyn crate::decode::DecodeOutputSink,
    ) {
        match self {
            Self::Shared(decoder) => decoder.decode_chunk_into(chunk, sink),
            Self::Reverse => ReverseDecoder.decode_chunk_with_policy_into(chunk, policy, sink),
            Self::Caesar => CaesarDecoder.decode_chunk_with_policy_into(chunk, policy, sink),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DecoderRegistrationError {
    #[error("decoder name must be non-empty ASCII without whitespace")]
    InvalidName,
    #[error("decoder {name:?} version must be non-empty ASCII without whitespace")]
    InvalidVersion { name: &'static str },
    #[error("decoder name {0:?} is already registered")]
    DuplicateName(&'static str),
    #[error("decoder identity list is incompatible: {0}")]
    IncompatibleIdentity(String),
    #[error("could not compile the all-decoder trigger automaton: {0}")]
    TriggerBuild(String),
}

#[derive(Clone)]
pub(crate) struct CompiledDecoderPlan {
    decoders: Arc<Vec<RegisteredDecoder>>,
    all_decoder_trigger: Option<AhoCorasick>,
    identity: u64,
}

impl std::fmt::Debug for CompiledDecoderPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompiledDecoderPlan")
            .field("decoder_count", &self.decoders.len())
            .field(
                "has_all_decoder_trigger",
                &self.all_decoder_trigger.is_some(),
            )
            .field("identity", &self.identity)
            .finish()
    }
}

impl CompiledDecoderPlan {
    pub(crate) fn snapshot() -> Result<Self, DecoderRegistrationError> {
        let decoders = snapshot_decoders()?;
        let mut names = std::collections::HashSet::with_capacity(decoders.len());
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"keyhog-compiled-decoder-plan-v1\0");
        for decoder in decoders.iter() {
            let name = decoder.name();
            let version = decoder.version();
            validate_descriptor(name, version)?;
            if !names.insert(name) {
                return Err(DecoderRegistrationError::DuplicateName(name));
            }
            hash_descriptor(&mut hasher, name, version);
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hasher.finalize().as_bytes()[..8]);
        let all_decoder_trigger = compile_all_decoder_trigger(&decoders)?;
        Ok(Self {
            decoders,
            all_decoder_trigger,
            identity: u64::from_le_bytes(bytes),
        })
    }

    /// Stable ordered identities persisted by execution packs. Decoder trait
    /// objects stay process-local and are reconstructed from this exact list.
    pub(crate) fn stable_identities(&self) -> Vec<String> {
        self.decoders
            .iter()
            .map(|decoder| format!("{}@{}", decoder.name(), decoder.version()))
            .collect()
    }

    pub(crate) fn from_stable_identities(
        expected: &[String],
    ) -> Result<Self, DecoderRegistrationError> {
        let plan = Self::snapshot()?;
        let actual = plan.stable_identities();
        if actual != expected {
            return Err(DecoderRegistrationError::IncompatibleIdentity(format!(
                "execution pack requires {expected:?}, but this runtime provides {actual:?}"
            )));
        }
        Ok(plan)
    }

    pub(crate) fn identity(&self) -> u64 {
        self.identity
    }

    #[cfg(any(feature = "decode", test))]
    pub(crate) fn decoders(&self) -> &[RegisteredDecoder] {
        &self.decoders
    }

    pub(crate) fn all_decoder_may_match(&self, data: &str) -> bool {
        self.all_decoder_trigger
            .as_ref()
            .is_none_or(|trigger| trigger.is_match(data.as_bytes()))
    }

    pub(crate) fn uses_only_default_decoders(&self) -> bool {
        self.all_decoder_trigger.is_some()
    }

    pub(crate) fn admission_context_key(&self, chunk: &keyhog_core::Chunk) -> Option<u8> {
        self.decoders.iter().try_fold(0, |context, decoder| {
            decoder
                .admission_context_key(chunk)
                .map(|decoder_context| context | decoder_context)
        })
    }
}

fn validate_descriptor(
    name: &'static str,
    version: &'static str,
) -> Result<(), DecoderRegistrationError> {
    if name.is_empty() || !name.is_ascii() || name.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(DecoderRegistrationError::InvalidName);
    }
    if version.is_empty()
        || !version.is_ascii()
        || version.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(DecoderRegistrationError::InvalidVersion { name });
    }
    Ok(())
}

fn hash_descriptor(hasher: &mut blake3::Hasher, name: &str, version: &str) {
    for value in [name.as_bytes(), version.as_bytes()] {
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value);
    }
}

fn is_default_decoder_name(name: &str) -> bool {
    matches!(
        name,
        "base64"
            | "hex"
            | "url"
            | "quoted-printable"
            | "html-named-entity"
            | "html-numeric-entity"
            | "octal-escape"
            | "mime-encoded-word"
            | "json"
            | "unicode-escape"
            | "z85"
            | "javascript-static"
            | "reverse"
            | "caesar"
    )
}

fn compile_all_decoder_trigger(
    decoders: &[RegisteredDecoder],
) -> Result<Option<AhoCorasick>, DecoderRegistrationError> {
    if decoders
        .iter()
        .any(|decoder| !is_default_decoder_name(decoder.name()))
    {
        return Ok(None);
    }
    let patterns = (b'!'..=b'~').map(|byte| [byte]);
    AhoCorasick::builder()
        .kind(Some(aho_corasick::AhoCorasickKind::ContiguousNFA))
        .build(patterns)
        .map(Some)
        .map_err(|error| DecoderRegistrationError::TriggerBuild(error.to_string()))
}

#[cfg(test)]
thread_local! {
    static THREAD_DECODERS: RefCell<Vec<Arc<dyn Decoder>>> = RefCell::new(Vec::new());
}

/// Per-decoder wall-time profiler (measurement only). Gated on the single
/// process-wide measurement level owned by `keyhog_profile`, at the diagnostic
/// step, because it costs a clock read per decoder call. Records which decoder
/// dominates decode generation. Zero-cost when the level is below diagnostic.
pub(super) fn profile_enabled() -> bool {
    crate::scan_profile::diagnostic()
}

/// Fixed number of per-decoder profiler slots, owned by the profile registry.
/// There are 14 default decoders today, so the cap carries headroom. A decoder
/// past the last slot is not folded into the last one: `add_indexed_counter`
/// counts it into the drained record's `dropped_out_of_range`, so
/// misattribution can never be silent. The
/// `decoder_registry_within_profiler_capacity` gap test guards the default set
/// against outgrowing the cap.
const MAX_PROFILED_DECODERS: usize = keyhog_profile::INDEXED_COUNTER_SLOTS;

/// Charge one decoder run to the profiler.
///
/// The storage is the profile runtime's indexed counter family. The scanner
/// used to hold two `[AtomicU64; 16]` arrays plus its own dump and its own
/// reset here, which was the last measurement store outside `keyhog-profile`.
/// Labels stay here because the profiler never needs the decoder's name: it
/// counts slots, and this module knows slot `i` is `decoders[i].name()`.
pub(super) fn record_decoder_run(
    decoder_index: usize,
    elapsed: std::time::Duration,
    produced: usize,
) {
    let Ok(slot) = u16::try_from(decoder_index) else {
        return;
    };
    keyhog_profile::add_indexed_counter(
        keyhog_profile::IndexedCounterId::DecoderElapsedNs,
        slot,
        // LAW10: profiler duration saturates on impossible u128-to-u64 overflow; decoder behavior is unchanged.
        u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
    );
    keyhog_profile::add_indexed_counter(
        keyhog_profile::IndexedCounterId::DecoderSubchunksEmitted,
        slot,
        produced as u64,
    );
}

/// Print the accumulated per-decoder times and emission counts, paired with
/// registry names. Folded into the unified scanner profile dump. The drain is
/// the profile runtime's, so there is no scanner-side reset to keep in step.
pub(crate) fn decoder_profile_dump() {
    let Some(runtime) = keyhog_profile::current_runtime() else {
        return;
    };
    let mut elapsed_ns = [0_u64; MAX_PROFILED_DECODERS];
    let mut emitted = [0_u64; MAX_PROFILED_DECODERS];
    let mut dropped = 0_u64;
    for record in runtime.take_session_indexed_counters() {
        let target = match record.counter {
            keyhog_profile::IndexedCounterId::DecoderElapsedNs => &mut elapsed_ns,
            keyhog_profile::IndexedCounterId::DecoderSubchunksEmitted => &mut emitted,
        };
        for (slot, value) in record.slots.iter().enumerate().take(MAX_PROFILED_DECODERS) {
            target[slot] = *value;
        }
        dropped = dropped.max(record.dropped_out_of_range);
    }

    let decoders = active_decoders();
    let named = decoders.len().min(MAX_PROFILED_DECODERS);
    let mut rows: Vec<(&str, f64)> = (0..named)
        .map(|i| (decoders[i].name(), elapsed_ns[i] as f64 / 1e6))
        .collect();
    rows.sort_by(|a, b| b.1.total_cmp(&a.1));
    let total: f64 = rows.iter().map(|row| row.1).sum();
    let mut prod: Vec<(&str, u64)> = (0..named)
        .map(|i| (decoders[i].name(), emitted[i]))
        .collect();
    prod.sort_by(|a, b| b.1.cmp(&a.1));
    let prod_total: u64 = prod.iter().map(|row| row.1).sum();
    if total == 0.0 && prod_total == 0 && dropped == 0 {
        return;
    }
    if dropped != 0 {
        // Never print a table that silently omits work. A nonzero drop means a
        // decoder registered past the fixed slot range and its time is in
        // neither row below.
        eprintln!(
            "  ⚠ {dropped} per-decoder record(s) addressed a slot past {MAX_PROFILED_DECODERS} and are absent from both tables below"
        );
    }
    eprintln!("=== per-decoder decode_chunk time ===");
    for (name, ms) in &rows {
        let pct = if total > 0.0 { 100.0 * ms / total } else { 0.0 };
        eprintln!("  {name:<18}: {ms:>8.1} ms ({pct:>5.1}%)");
    }
    eprintln!("  {:<18}: {total:>8.1} ms", "TOTAL");
    eprintln!("=== per-decoder sub-chunks EMITTED (pre-dedup/screen) ===");
    for (name, n) in &prod {
        let pct = if prod_total > 0 {
            100.0 * *n as f64 / prod_total as f64
        } else {
            0.0
        };
        eprintln!("  {name:<18}: {n:>8} ({pct:>5.1}%)");
    }
    eprintln!("  {:<18}: {prod_total:>8}", "TOTAL");
}

fn default_decoders() -> Vec<RegisteredDecoder> {
    vec![
        RegisteredDecoder::Shared(Arc::new(Base64Decoder)),
        RegisteredDecoder::Shared(Arc::new(HexDecoder)),
        RegisteredDecoder::Shared(Arc::new(UrlDecoder)),
        RegisteredDecoder::Shared(Arc::new(QuotedPrintableDecoder)),
        RegisteredDecoder::Shared(Arc::new(HtmlNamedEntityDecoder)),
        RegisteredDecoder::Shared(Arc::new(HtmlNumericEntityDecoder)),
        RegisteredDecoder::Shared(Arc::new(OctalEscapeDecoder)),
        RegisteredDecoder::Shared(Arc::new(MimeEncodedWordDecoder)),
        // JSON unescape - strips `\"` / `\\` / `\n` style escapes inside JSON
        // string values so credentials stored as JSON-encoded fields survive
        // into the scanner.
        RegisteredDecoder::Shared(Arc::new(JsonDecoder)),
        RegisteredDecoder::Shared(Arc::new(UnicodeEscapeDecoder)),
        RegisteredDecoder::Shared(Arc::new(Z85Decoder)),
        // Bounded, side-effect-free JavaScript constant recovery. Keep it after
        // representation decoders and before the asymmetric evasion decoders.
        #[cfg(feature = "decode")]
        RegisteredDecoder::Shared(Arc::new(JavaScriptStaticDecoder)),
        RegisteredDecoder::Reverse,
        RegisteredDecoder::Caesar,
    ]
}

/// The `name()` of each default decoder, in registration order. This is the
/// canonical decode-pipeline composition, the order is load-bearing (the
/// `reverse` and `caesar` decoders deliberately run last, after the structural
/// decoders), and is pinned by `decoder_registry_default_order` so a reorder
/// or addition can't silently shift the pipeline.
#[cfg(feature = "decode")]
pub(crate) fn default_decoder_names() -> Vec<&'static str> {
    default_decoders().iter().map(|d| d.name()).collect()
}

/// Aggregate decoder-owned admission proofs for one root chunk.
///
/// Candidate extraction is primed once so built-in predicates that use the
/// shared extractor do not each allocate and rescan independently. Any custom
/// decoder that keeps the trait default returns `Unknown`, which is preserved
/// unless another decoder already proves the chunk is `Possible`.
#[cfg(feature = "decode")]
pub(crate) fn decoder_admission(
    chunk: &keyhog_core::Chunk,
    policy: &super::super::policy::CompiledDecodeTransformPolicy,
    plan: &CompiledDecoderPlan,
) -> DecodeAdmission {
    super::extractor::clear_shared_candidates();
    super::extractor::prime_shared_candidates(&chunk.data, plan.uses_only_default_decoders());

    let mut aggregate = DecodeAdmission::Impossible;
    for decoder in plan.decoders() {
        match decoder.admission(chunk, policy) {
            DecodeAdmission::Possible => {
                aggregate = DecodeAdmission::Possible;
                break;
            }
            DecodeAdmission::Unknown => aggregate = DecodeAdmission::Unknown,
            DecodeAdmission::Impossible => {}
        }
    }

    super::extractor::clear_shared_candidates();
    aggregate
}

#[cfg(any(feature = "decode", test))]
pub(crate) fn decoder_admission_sketch(
    chunk: &keyhog_core::Chunk,
    policy: &super::super::policy::CompiledDecodeTransformPolicy,
    plan: &CompiledDecoderPlan,
) -> DecodeAdmissionSketch {
    decoder_admission_sketch_with_decoders(chunk, policy, plan.decoders())
}

#[cfg(any(feature = "decode", test))]
pub(crate) fn active_decoder_admission_sketch(
    chunk: &keyhog_core::Chunk,
    policy: &super::super::policy::CompiledDecodeTransformPolicy,
) -> DecodeAdmissionSketch {
    let decoders = active_decoders();
    decoder_admission_sketch_with_decoders(chunk, policy, &decoders)
}

#[cfg(any(feature = "decode", test))]
fn decoder_admission_sketch_with_decoders(
    chunk: &keyhog_core::Chunk,
    policy: &super::super::policy::CompiledDecodeTransformPolicy,
    decoders: &[RegisteredDecoder],
) -> DecodeAdmissionSketch {
    super::extractor::clear_shared_candidates();
    super::extractor::prime_shared_candidates(
        &chunk.data,
        decoders
            .iter()
            .all(|decoder| is_default_decoder_name(decoder.name())),
    );

    let mut aggregate = DecodeAdmissionSketch::NONE;
    for decoder in decoders {
        aggregate.merge(decoder.admission_sketch(chunk, policy));
    }

    super::extractor::clear_shared_candidates();
    aggregate
}

fn decoder_registry() -> &'static RwLock<DecoderRegistryState> {
    DECODERS.get_or_init(|| {
        RwLock::new(DecoderRegistryState {
            decoders: Arc::new(default_decoders()),
            compatibility_failure: None,
        })
    })
}

#[cfg(not(test))]
pub(super) fn active_decoders() -> Arc<Vec<RegisteredDecoder>> {
    // One `Arc` clone (a single atomic increment) instead of deep-cloning the
    // decoder Vec on every `decode_chunk`. Callers only iterate, so the shared
    // snapshot suffices.
    Arc::clone(&decoder_registry().read().decoders)
}

#[cfg(test)]
pub(super) fn active_decoders() -> Arc<Vec<RegisteredDecoder>> {
    let base = Arc::clone(&decoder_registry().read().decoders);
    THREAD_DECODERS.with(|thread_decoders| {
        let thread = thread_decoders.borrow();
        if thread.is_empty() {
            // Common case: no per-test decoder registered, hand back the shared
            // snapshot with no allocation, matching the non-test fast path.
            base
        } else {
            let mut combined = (*base).clone();
            combined.extend(thread.iter().cloned().map(RegisteredDecoder::Shared));
            Arc::new(combined)
        }
    })
}

#[cfg(not(test))]
fn snapshot_decoders() -> Result<Arc<Vec<RegisteredDecoder>>, DecoderRegistrationError> {
    let registry = decoder_registry().read();
    if let Some(error) = registry.compatibility_failure.clone() {
        Err(error)
    } else {
        Ok(Arc::clone(&registry.decoders))
    }
}

#[cfg(test)]
fn snapshot_decoders() -> Result<Arc<Vec<RegisteredDecoder>>, DecoderRegistrationError> {
    let base = {
        let registry = decoder_registry().read();
        if let Some(error) = registry.compatibility_failure.clone() {
            return Err(error);
        }
        Arc::clone(&registry.decoders)
    };
    THREAD_DECODERS.with(|thread_decoders| {
        let thread = thread_decoders.borrow();
        if thread.is_empty() {
            Ok(base)
        } else {
            let mut combined = (*base).clone();
            combined.extend(thread.iter().cloned().map(RegisteredDecoder::Shared));
            Ok(Arc::new(combined))
        }
    })
}

/// Register a custom decoder for scanners compiled afterward.
///
/// Use [`try_register_decoder`] when the caller can handle a registration
/// error. This compatibility entry point records any error, and later scanner
/// compilation returns it. Existing compiled scanners retain their immutable
/// decoder plan.
pub fn register_decoder(decoder: Box<dyn Decoder>) {
    if let Err(error) = register_decoder_inner(decoder, true) {
        tracing::error!(%error, "decoder registration failed; later scanner compilation will fail");
    }
}

/// Register a custom decoder and return descriptor or collision errors.
///
/// The name and version must be non-empty ASCII without whitespace. A name can
/// be registered only once. Existing compiled scanners retain their immutable
/// decoder plan.
pub fn try_register_decoder(decoder: Box<dyn Decoder>) -> Result<(), DecoderRegistrationError> {
    register_decoder_inner(decoder, false)
}

fn register_decoder_inner(
    decoder: Box<dyn Decoder>,
    record_failure: bool,
) -> Result<(), DecoderRegistrationError> {
    let decoder_name = decoder.name();
    let mut guard = decoder_registry().write();
    if let Some(error) = guard.compatibility_failure.clone() {
        return Err(error);
    }
    let result = validate_descriptor(decoder_name, decoder.version()).and_then(|()| {
        if guard
            .decoders
            .iter()
            .any(|existing| existing.name() == decoder_name)
        {
            Err(DecoderRegistrationError::DuplicateName(decoder_name))
        } else {
            Ok(())
        }
    });
    if let Err(error) = result {
        if record_failure && guard.compatibility_failure.is_none() {
            guard.compatibility_failure = Some(error.clone());
        }
        return Err(error);
    }
    // Copy-on-write: publish a fresh snapshot so any `active_decoders()` Arc
    // already handed out keeps its consistent view. Registration happens at
    // startup / test setup, never on the decode hot path, so this one-time Vec
    // clone is not a concern.
    let mut next = (*guard.decoders).clone();
    next.push(RegisteredDecoder::Shared(Arc::from(decoder)));
    guard.decoders = Arc::new(next);
    Ok(())
}

#[cfg(test)]
pub(crate) struct ScopedDecoderRegistration {
    name: &'static str,
    active: bool,
}

#[cfg(test)]
impl Drop for ScopedDecoderRegistration {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        THREAD_DECODERS.with(|thread_decoders| {
            let mut decoders = thread_decoders.borrow_mut();
            if let Some(index) = decoders
                .iter()
                .rposition(|decoder| decoder.name() == self.name)
            {
                decoders.remove(index);
            }
        });
    }
}

#[cfg(test)]
pub(crate) fn register_thread_decoder(decoder: Box<dyn Decoder>) -> ScopedDecoderRegistration {
    let decoder_name = decoder.name();
    let has_global_duplicate = decoder_registry()
        .read()
        .decoders
        .iter()
        .any(|existing| existing.name() == decoder_name);
    if has_global_duplicate {
        tracing::warn!(
            decoder = decoder_name,
            "register_thread_decoder called with a duplicate global decoder name; decoder ignored"
        );
        return ScopedDecoderRegistration {
            name: decoder_name,
            active: false,
        };
    }

    let mut inserted = false;
    let decoder = Arc::from(decoder);
    THREAD_DECODERS.with(|thread_decoders| {
        let mut decoders = thread_decoders.borrow_mut();
        if decoders.iter().any(|existing| existing.name() == decoder_name) {
            tracing::warn!(
                decoder = decoder_name,
                "register_thread_decoder called with a duplicate thread decoder name; decoder ignored"
            );
            return;
        }
        decoders.push(decoder);
        inserted = true;
    });
    ScopedDecoderRegistration {
        name: decoder_name,
        active: inserted,
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/decode_admission_soundness.rs"]
mod admission_soundness_tests;
