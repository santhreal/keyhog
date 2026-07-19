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
#[cfg(feature = "decode")]
use crate::decode::DecodeAdmission;
#[cfg(any(feature = "decode", test))]
use crate::decode::DecodeAdmissionSketch;
use crate::decode::Decoder;
use parking_lot::RwLock;
#[cfg(test)]
use std::cell::RefCell;
use std::sync::Arc;

// The active decoder set is stored behind ONE shared `Arc<Vec<..>>` so the
// per-`decode_chunk` `active_decoders()` read hands back a refcount bump instead
// of deep-cloning the 14-decoder Vec (14 Arc bumps + a heap allocation) on every
// chunk. Mutation (`register_decoder`) is copy-on-write, so in-flight readers
// keep a consistent snapshot.
static DECODERS: std::sync::OnceLock<RwLock<Arc<Vec<RegisteredDecoder>>>> =
    std::sync::OnceLock::new();

#[derive(Clone)]
pub(super) enum RegisteredDecoder {
    Shared(Arc<dyn Decoder>),
    Reverse,
    Caesar,
}

impl RegisteredDecoder {
    fn name(&self) -> &'static str {
        match self {
            Self::Shared(decoder) => decoder.name(),
            Self::Reverse => "reverse",
            Self::Caesar => "caesar",
        }
    }

    #[cfg(feature = "decode")]
    fn admission(
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

    pub(super) fn decode_chunk(
        &self,
        chunk: &keyhog_core::Chunk,
        policy: &super::super::policy::CompiledDecodeTransformPolicy,
    ) -> Vec<keyhog_core::Chunk> {
        match self {
            Self::Shared(decoder) => decoder.decode_chunk(chunk),
            Self::Reverse => ReverseDecoder.decode_chunk_with_policy(chunk, policy),
            Self::Caesar => CaesarDecoder.decode_chunk_with_policy(chunk, policy),
        }
    }
}

#[cfg(test)]
thread_local! {
    static THREAD_DECODERS: RefCell<Vec<Arc<dyn Decoder>>> = RefCell::new(Vec::new());
}

/// Per-decoder wall-time profiler (measurement only). Enabled by the single
/// scanner profiler switch (`keyhog scan --profile`) so profiling has one runtime
/// owner instead of one env knob per pass. Records which decoder dominates
/// decode generation. Zero-cost unset.
pub(super) fn profile_enabled() -> bool {
    crate::engine::profile::enabled()
}

/// Fixed number of per-decoder profiler slots. The `DECODER_NS` / `DECODER_PRODUCED`
/// accumulators and every index/clamp into them share this one capacity. There
/// are 14 default decoders today, so the cap carries headroom; a decoder past
/// slot `MAX_PROFILED_DECODERS` is simply not profiled (`record_decoder_run`
/// drops it), the `decoder_registry_within_profiler_capacity` gap test guards
/// the default set against silently outgrowing this.
const MAX_PROFILED_DECODERS: usize = 16;

static DECODER_NS: [std::sync::atomic::AtomicU64; MAX_PROFILED_DECODERS] = {
    const Z: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    [Z; MAX_PROFILED_DECODERS]
};

/// Sub-chunks EMITTED per decoder (pre-dedup/screen). The sub-chunk COUNT - not
/// gen time - is what drives the dominant decode-rescan + per-sub-chunk fixed
/// phase-1 cost, so this isolates which decoders to gate with a sound prune.
static DECODER_PRODUCED: [std::sync::atomic::AtomicU64; MAX_PROFILED_DECODERS] = {
    const Z: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    [Z; MAX_PROFILED_DECODERS]
};

pub(super) fn record_decoder_run(
    decoder_index: usize,
    elapsed: std::time::Duration,
    produced: usize,
) {
    if decoder_index >= MAX_PROFILED_DECODERS {
        return;
    }
    use std::sync::atomic::Ordering::Relaxed;
    DECODER_NS[decoder_index].fetch_add(elapsed.as_nanos() as u64, Relaxed);
    DECODER_PRODUCED[decoder_index].fetch_add(produced as u64, Relaxed);
}

/// Print and reset the accumulated per-decoder times (paired with registry
/// names). Folded into the unified scanner profile dump.
pub(crate) fn decoder_profile_dump() {
    use std::sync::atomic::Ordering::Relaxed;
    let decoders = active_decoders();
    let names: Vec<&str> = decoders.iter().map(|d| d.name()).collect();
    let mut rows: Vec<(String, f64)> = (0..names.len().min(MAX_PROFILED_DECODERS))
        .map(|i| {
            (
                names[i].to_string(),
                DECODER_NS[i].swap(0, Relaxed) as f64 / 1e6,
            )
        })
        .collect();
    rows.sort_by(|a, b| b.1.total_cmp(&a.1));
    let total: f64 = rows.iter().map(|r| r.1).sum();
    let mut prod: Vec<(String, u64)> = (0..names.len().min(MAX_PROFILED_DECODERS))
        .map(|i| (names[i].to_string(), DECODER_PRODUCED[i].swap(0, Relaxed)))
        .collect();
    prod.sort_by(|a, b| b.1.cmp(&a.1));
    let prod_total: u64 = prod.iter().map(|r| r.1).sum();
    if total == 0.0 && prod_total == 0 {
        return;
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

pub(crate) fn decoder_profile_reset() {
    use std::sync::atomic::Ordering::Relaxed;
    for slot in &DECODER_NS {
        slot.store(0, Relaxed);
    }
    for slot in &DECODER_PRODUCED {
        slot.store(0, Relaxed);
    }
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
) -> DecodeAdmission {
    let decoders = active_decoders();
    super::extractor::clear_shared_candidates();
    super::extractor::prime_shared_candidates(&chunk.data);

    let mut aggregate = DecodeAdmission::Impossible;
    for decoder in decoders.iter() {
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
) -> DecodeAdmissionSketch {
    let decoders = active_decoders();
    super::extractor::clear_shared_candidates();
    super::extractor::prime_shared_candidates(&chunk.data);

    let mut aggregate = DecodeAdmissionSketch::NONE;
    for decoder in decoders.iter() {
        aggregate.merge(decoder.admission_sketch(chunk, policy));
    }

    super::extractor::clear_shared_candidates();
    aggregate
}

fn decoder_registry() -> &'static RwLock<Arc<Vec<RegisteredDecoder>>> {
    DECODERS.get_or_init(|| RwLock::new(Arc::new(default_decoders())))
}

#[cfg(not(test))]
pub(super) fn active_decoders() -> Arc<Vec<RegisteredDecoder>> {
    // One `Arc` clone (a single atomic increment) instead of deep-cloning the
    // decoder Vec on every `decode_chunk`. Callers only iterate, so the shared
    // snapshot suffices.
    Arc::clone(&decoder_registry().read())
}

#[cfg(test)]
pub(super) fn active_decoders() -> Arc<Vec<RegisteredDecoder>> {
    let base = Arc::clone(&decoder_registry().read());
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

/// Register a custom decoder.
pub fn register_decoder(decoder: Box<dyn Decoder>) {
    let decoder_name = decoder.name();
    let mut guard = decoder_registry().write();
    if guard.iter().any(|existing| existing.name() == decoder_name) {
        tracing::warn!(
            decoder = decoder_name,
            "register_decoder called with a duplicate decoder name; decoder ignored"
        );
        return;
    }
    // Copy-on-write: publish a fresh snapshot so any `active_decoders()` Arc
    // already handed out keeps its consistent view. Registration happens at
    // startup / test setup, never on the decode hot path, so this one-time Vec
    // clone is not a concern.
    let mut next = (**guard).clone();
    next.push(RegisteredDecoder::Shared(Arc::from(decoder)));
    *guard = Arc::new(next);
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
