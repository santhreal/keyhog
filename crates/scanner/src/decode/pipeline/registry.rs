use crate::decode::base64::{Base64Decoder, Z85Decoder};
use crate::decode::caesar::CaesarDecoder;
use crate::decode::hex::HexDecoder;
use crate::decode::json::JsonDecoder;
use crate::decode::reverse::ReverseDecoder;
use crate::decode::url::{
    HexEscapeDecoder, HtmlNamedEntityDecoder, HtmlNumericEntityDecoder, MimeEncodedWordDecoder,
    OctalEscapeDecoder, QuotedPrintableDecoder, UnicodeEscapeDecoder, UrlDecoder,
};
use crate::decode::Decoder;
use parking_lot::RwLock;
#[cfg(test)]
use std::cell::RefCell;
use std::sync::Arc;

static DECODERS: std::sync::OnceLock<RwLock<Vec<Arc<dyn Decoder>>>> = std::sync::OnceLock::new();

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

static DECODER_NS: [std::sync::atomic::AtomicU64; 16] = {
    const Z: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    [Z; 16]
};

/// Sub-chunks EMITTED per decoder (pre-dedup/screen). The sub-chunk COUNT - not
/// gen time - is what drives the dominant decode-rescan + per-sub-chunk fixed
/// phase-1 cost, so this isolates which decoders to gate with a sound prune.
static DECODER_PRODUCED: [std::sync::atomic::AtomicU64; 16] = {
    const Z: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    [Z; 16]
};

pub(super) fn record_decoder_run(
    decoder_index: usize,
    elapsed: std::time::Duration,
    produced: usize,
) {
    if decoder_index >= 16 {
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
    let mut rows: Vec<(String, f64)> = (0..names.len().min(16))
        .map(|i| {
            (
                names[i].to_string(),
                DECODER_NS[i].swap(0, Relaxed) as f64 / 1e6,
            )
        })
        .collect();
    rows.sort_by(|a, b| b.1.total_cmp(&a.1));
    let total: f64 = rows.iter().map(|r| r.1).sum();
    let mut prod: Vec<(String, u64)> = (0..names.len().min(16))
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

fn default_decoders() -> Vec<Arc<dyn Decoder>> {
    vec![
        Arc::new(Base64Decoder),
        Arc::new(HexDecoder),
        Arc::new(UrlDecoder),
        Arc::new(QuotedPrintableDecoder),
        Arc::new(HtmlNamedEntityDecoder),
        Arc::new(HtmlNumericEntityDecoder),
        Arc::new(HexEscapeDecoder),
        Arc::new(OctalEscapeDecoder),
        Arc::new(MimeEncodedWordDecoder),
        // JSON unescape - strips `\"` / `\\` / `\n` style escapes inside JSON
        // string values so credentials stored as JSON-encoded fields survive
        // into the scanner.
        Arc::new(JsonDecoder),
        Arc::new(UnicodeEscapeDecoder),
        Arc::new(Z85Decoder),
        Arc::new(ReverseDecoder),
        Arc::new(CaesarDecoder),
    ]
}

fn decoder_registry() -> &'static RwLock<Vec<Arc<dyn Decoder>>> {
    DECODERS.get_or_init(|| RwLock::new(default_decoders()))
}

#[cfg(not(test))]
pub(super) fn active_decoders() -> Vec<Arc<dyn Decoder>> {
    decoder_registry().read().clone()
}

#[cfg(test)]
pub(super) fn active_decoders() -> Vec<Arc<dyn Decoder>> {
    let mut decoders = decoder_registry().read().clone();
    THREAD_DECODERS.with(|thread_decoders| {
        decoders.extend(thread_decoders.borrow().iter().cloned());
    });
    decoders
}

/// Register a custom decoder.
pub fn register_decoder(decoder: Box<dyn Decoder>) {
    let decoder_name = decoder.name();
    let mut decoders = decoder_registry().write();
    if decoders
        .iter()
        .any(|existing| existing.name() == decoder_name)
    {
        tracing::warn!(
            decoder = decoder_name,
            "register_decoder called with a duplicate decoder name; decoder ignored"
        );
        return;
    }
    decoders.push(Arc::from(decoder));
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
