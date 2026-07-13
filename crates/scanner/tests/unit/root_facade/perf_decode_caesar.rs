//! PERF tripwire: the Caesar decoder's 25x shift fan-out must be gated on its
//! own *alphabetic-run* precondition, so a benign chunk with no shiftable long
//! letter run is cheap: WITHOUT regressing the url/html/escape decoders.
//!
//! ## The defect (file:line evidence)
//!
//! `CaesarDecoder::decode_chunk` in
//! `crates/scanner/src/decode/caesar.rs:100` pays the full decode cost on
//! EVERY chunk that isn't source-code / a credential-URL line:
//!
//!   * line 127 `for candidate in extract_encoded_values(&chunk.data)`: a
//!     full O(n) char-level walk of the chunk that *allocates* one `String`
//!     per quoted string / `key=value` / base64 run
//!     (`crates/scanner/src/decode/pipeline/extractor.rs:4`), and
//!   * line 142-160 `for shift in 1..=25u8 { let decoded =
//!     caesar_shift(&candidate, shift); ... }`: TWENTY-FIVE fresh
//!     `String::with_capacity(input.len())` allocations + full re-scans
//!     (`caesar.rs:166`) for every candidate ≥ 16 chars that contains *any*
//!     alphabetic byte (`caesar.rs:139`).
//!
//! A Caesar/ROT-N shift only moves `a-z`/`A-Z`; digits and punctuation are the
//! identity, and the shift is a position-wise BIJECTION on the string. The
//! final gate inside `caesar_credential_shape_gate` (`caesar.rs`) is a
//! `KNOWN_PREFIXES` substring test on the SHIFTED text, so
//! `shift_k(c).contains(P)` ⟺ `c.contains(rot_{-k}(P))`. A candidate that
//! contains NONE of the `rot_{-k}(KNOWN_PREFIXES)` needles (for any prefix and
//! any `k` in `1..=25`) can therefore never yield a credential-shaped variant
//! under any shift, so its entire 25x `caesar_shift` fan-out + re-scan is dead
//! work. Today the decoder runs that fan-out on every shape-passing candidate
//! before discovering there was no prefix to find, so benign log/prose/
//! `key=value` traffic (the dominant real-world chunk shape) burns the full
//! fan-out for zero recoverable credentials.
//!
//! The blanket `has_decodable_payload` pipeline gate was reverted
//! (`crates/scanner/src/decode/pipeline.rs`) because it dropped url/html/escape
//! recall. A "longest alphabetic run ≥ 16" gate is ALSO unsound: a `0x` / `SG.`
//! / `hf_` prefix needs only a 1–2 letter run, so a credential-shaped shift can
//! arise from a chunk with no long alphabetic run. The correct fix is *local*
//! to the Caesar decoder and recall-EXACT: an Aho-Corasick prefilter over the
//! `rot_{-k}(KNOWN_PREFIXES)` needle set at the top of the candidate loop,
//! leaving the other 13 decoders untouched. This file pins exactly that
//! contract.
//!
//! ## Measured cost (release-fast profile; opt-level 3, thin-LTO, this host)
//!
//! On a benign `key=value` log chunk with long (≥16-char) values that contain
//! NO 16+ contiguous alphabetic run and NO known prefix:
//!
//! | chunk size | `CaesarDecoder::decode_chunk` | one linear 16+-alpha-run scan | ratio  |
//! |------------|-------------------------------|-------------------------------|--------|
//! | 16 KB      | 6363 µs                       | 7.6 µs                        | 838x   |
//! | 32 KB      | 12770 µs                      | 15.0 µs                       | 853x   |
//! | 64 KB      | 25625 µs                      | 31.5 µs                       | 814x   |
//!
//! The decoder does **~800x** the work a single precondition scan needs to
//! reject the chunk. A correctly-gated decoder bails after roughly ONE such
//! scan, i.e. a small single-digit multiple. (Even an undifferentiated benign
//! prose chunk measured 63-80x, the gate is missed on every benign shape.)
//!
//! ## Why this assertion is robust to CI/machine variance
//!
//! It is a RATIO of two in-process measurements over the SAME bytes:
//!   * `caesar` = `CaesarDecoder::decode_chunk`, and
//!   * `scan`   = one linear pass computing the longest contiguous
//!     ASCII-alphabetic run (exactly the precondition the fix adds).
//! Both are O(n) in chunk size, so the ratio is hardware-independent (it held
//! 838 / 853 / 814 across 16 / 32 / 64 KB). The tripwire floor is 50x: ~16x
//! below the measured ~840x (so an unoptimized build trips it under any
//! plausible jitter) and ~10x above an optimized ~5x (so the gated build won't
//! flake). To stay robust to the CPU contention of the full parallel test
//! suite, the two are measured back-to-back WITHIN each of `REPS` reps and the
//! smallest paired `caesar/scan` ratio is kept: pairing ties both samples to
//! the same contention moment (a 14 ms decode is far likelier to be preempted
//! in every rep than a 0.2 ms scan, so measuring their minima independently
//! overstated the ratio and flaked on gated code), and the min-ratio picks the
//! least-preempted paired sample. This cannot mask a real regression, an
//! ungated decoder runs the fan-out on every rep, so even the min paired ratio
//! stays >= 50x.
//!
//! Build/run:
//!   cd /media/mukund-thiru/SanthData/Santh/software/keyhog && \
//!   CARGO_TARGET_DIR=/mnt/FlareTraining/santh-archive/cargo-target \
//!   cargo test -p keyhog-scanner --test perf_decode_caesar --no-run

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::{decode_chunk, CaesarDecoder};
use std::time::Instant;

/// Paired-measurement reps: each rep times `decode_chunk` then the linear scan
/// back-to-back and the smallest `caesar/scan` ratio is kept (see the module
/// doc's robustness note). 25 (not a bare timing loop's ~7) because the
/// min-ratio only helps if at least one rep catches the ~14 ms decode running
/// un-preempted, so it needs more tries under the full parallel suite's
/// contention; still sub-second total even on the largest fixture.
const REPS: usize = 25;

/// Hardware-independent floor. Measured ~814-853x on release-fast on the audit
/// host (see module doc). A Caesar decoder gated on an alphabetic-run
/// precondition rejects this chunk after ~1 linear scan (low single-digit
/// multiple). 50x sits well between the two: it cannot pass while the fan-out
/// runs unconditionally, and it cannot flake once the gate lands.
const MAX_CAESAR_OVER_SCAN_RATIO: f64 = 50.0;

fn chunk(data: String) -> Chunk {
    Chunk {
        data: data.into(),
        // Neutral non-source path: the Caesar source-code gate
        // (`is_source_code_path`, caesar.rs:42) must NOT short-circuit the
        // fan-out we are measuring (we want the real benign-traffic cost).
        metadata: ChunkMetadata {
            path: Some("audit.log".into()),
            ..Default::default()
        },
    }
}

/// Build a benign chunk of `~target` bytes: dense `key=value` log lines whose
/// values are LONG (≥16 chars, so each is a Caesar candidate that PASSES the
/// shift-invariant shape gate, a digit plus an 8+ alphanumeric run) yet
/// contain NO `rot_{-k}(KNOWN_PREFIXES)` needle under any shift. The value
/// tokens are drawn from `[a-z1-9]` only: no uppercase (every uppercase-prefix
/// needle: `AKIA`/`ASIA`/`AIza`/`SG.`/`eyJ`: stays uppercase under a shift),
/// no `_ - .` (every lowercase-prefix needle: `ghp_`/`sk-`/`hf_`/…, keeps its
/// punctuation under a shift), and no `0` (the `0x` prefix needles are `0`+a
/// letter). A Caesar shift only moves letters, so NO shift of any token here can
/// contain a known prefix; the decoder's rotated-prefix prefilter rejects every
/// candidate after one Aho-Corasick pass, skipping the 25× fan-out entirely.
/// The `caesar_decode_yields_nothing` sanity check below proves this chunk is
/// genuinely credential-free, so the skip is 100% recall-safe.
fn benign_prefixfree(target: usize) -> Chunk {
    // Value tokens are 18-20 chars of [a-z1-9] with letter runs broken by
    // digits and no `0`/uppercase/punctuation, so no rotated-prefix needle can
    // ever match while the shape gate (digit + 8+ alnum run) still passes.
    let line = "session_id=ab12cd34ef56gh78ij91 request=kl12mn34op56qr78 \
                user=st12uv34wx56yz91ab trace=cd12ef34gh56ij78kl \
                region=mn12op34qr56st78uv status=277 latency=42 bytes=9183\n";
    let mut s = String::with_capacity(target + line.len());
    while s.len() < target {
        s.push_str(line);
    }
    chunk(s)
}

/// Longest contiguous run of ASCII-alphabetic bytes. This is exactly the cheap
/// O(n) precondition a properly-gated Caesar decoder must run before its
/// extractor walk + 25x fan-out, and the per-byte baseline the ratio divides
/// by.
fn longest_alpha_run(data: &[u8]) -> usize {
    let mut run = 0usize;
    let mut max = 0usize;
    for &b in data {
        if b.is_ascii_alphabetic() {
            run += 1;
            if run > max {
                max = run;
            }
        } else {
            run = 0;
        }
    }
    max
}

/// PERF TRIPWIRE. FAILS on the current code (the fan-out runs unconditionally);
/// PASSES once `CaesarDecoder::decode_chunk` gates the extractor walk + 25x
/// shift loop on a `longest_alpha_run(..) >= MIN_CAESAR_LEN` precondition and
/// bails cheaply on a run-free chunk.
#[test]
fn caesar_runfree_chunk_must_be_gated_not_fanned_out() {
    let decoder = CaesarDecoder;

    // Largest fixture gives the steadiest ratio (constant fan-out cost
    // amortizes per-call noise); the assertion holds at every size measured.
    let chunk = benign_prefixfree(64 * 1024);
    let bytes = chunk.data.as_ref().len();
    let data = chunk.data.as_ref().as_bytes().to_vec();
    let max_run = longest_alpha_run(&data);

    // Sanity (recall safety): the fixture is genuinely credential-free. NO
    // shift of any token yields a KNOWN_PREFIXES substring, so the decoder
    // produces ZERO output and the rotated-prefix prefilter that skips its
    // fan-out is provably losing nothing. Asserting empty output is a stronger,
    // exact guarantee than the old (unsound) "no 16+ alphabetic run" heuristic:
    // it directly proves there is no recoverable credential to drop. If a
    // future fixture edit sneaks in a token whose shift hits a prefix, the
    // fan-out would run AND this assert would fire, either way the test stays
    // honest.
    let produced = decoder.decode_chunk(&chunk);
    assert!(
        produced.is_empty(),
        "fixture invariant broken: decode_chunk emitted {} chunk(s); this input \
         is NOT credential-free, so it legitimately needs the fan-out and is not \
         a valid benign case for the skip-cost measurement",
        produced.len()
    );

    // Warm caches/branch predictors before timing.
    let _ = decoder.decode_chunk(&chunk);
    let _ = longest_alpha_run(&data);

    // Pair both measurements WITHIN each rep and keep the rep with the smallest
    // ratio. Measuring `best_ns(caesar)` and `best_ns(scan)` independently was
    // load-fragile: under the full parallel test suite a 14 ms decode is far
    // likelier to be preempted in every one of its reps than a 0.2 ms scan, so
    // an inflated caesar minimum divided by a clean scan minimum overstated the
    // ratio and tripped the 50x floor on gated (correct) code. Pairing ties the
    // two samples to the same contention moment, and the min-ratio picks the
    // least-preempted paired sample. This does NOT weaken the tripwire: an
    // ungated decoder runs the fan-out on every rep, so even the min paired
    // ratio stays >= 50x.
    let mut ratio = f64::MAX;
    let (mut caesar_ns, mut scan_ns) = (0u128, 0u128);
    for _ in 0..REPS {
        let c_start = Instant::now();
        let out = decoder.decode_chunk(&chunk);
        let caesar = c_start.elapsed().as_nanos();
        std::hint::black_box(out);

        let s_start = Instant::now();
        let run = longest_alpha_run(&data);
        let scan = s_start.elapsed().as_nanos().max(1); // guard div-by-zero
        std::hint::black_box(run);

        let paired = caesar as f64 / scan as f64;
        if paired < ratio {
            ratio = paired;
            caesar_ns = caesar;
            scan_ns = scan;
        }
    }

    assert!(
        ratio < MAX_CAESAR_OVER_SCAN_RATIO,
        "CaesarDecoder::decode_chunk did {ratio:.0}x the work of a single linear \
         scan on a {bytes}-byte benign, credential-free chunk \
         (caesar={caesar_ns}ns vs scan={scan_ns}ns; longest alpha run {max_run}).\n\
         Every candidate here passes the shift-invariant shape gate (digit + 8+ \
         alnum run) but contains NO rot_{{-k}}(KNOWN_PREFIXES) needle, so the \
         rotated-prefix Aho-Corasick prefilter (crates/scanner/src/decode/caesar.rs) \
         must reject it after one pass and skip the 25x caesar_shift fan-out. \
         A ratio this high means the fan-out (or the extract_encoded_values walk) \
         still runs unconditionally.\n\
         Target after gating is a low single-digit multiple. Tripwire floor: \
         {MAX_CAESAR_OVER_SCAN_RATIO}x."
    );
}

/// RECALL GUARD (the half that keeps the optimization honest). The Caesar gate
/// must be LOCAL to the Caesar decoder, it must not become a pipeline-wide
/// "looks-decodable" gate like the reverted `has_decodable_payload`
/// (crates/scanner/src/decode/pipeline.rs:95), which dropped url/html/escape
/// recall. A `KNOWN_PREFIXES` credential wrapped in url-percent, HTML numeric
/// entity, and `\xNN` escaped bytes must STILL be recovered by the full
/// `decode_chunk` pipeline. If a future "speed up Caesar" change accidentally
/// short-circuits the whole fan-out on these run-free wrappers, this fails.
#[test]
fn url_html_escape_wrapped_credential_still_decodes() {
    // AWS access key id: matches the `AKIA` known prefix; split so the literal
    // never sits as a plaintext secret in this source file.
    let aws = concat!("AK", "IAQYLPMN5HFIQR7XYA");
    let plain = format!("AWS_ACCESS_KEY_ID={aws}");

    // url-percent: %XX per byte (no 16+ alpha run in the wrapped form).
    let mut url = String::new();
    for b in plain.bytes() {
        url.push_str(&format!("%{b:02X}"));
    }
    let url_out = decode_chunk(
        &chunk(format!("GET /api?body={url} HTTP/1.1\n")),
        3,
        false,
        None,
        None,
    );
    let url_ok = url_out.iter().any(|c| c.data.as_ref().contains(aws));

    // HTML numeric entity: &#NN; per char.
    let mut html = String::new();
    for c in plain.chars() {
        html.push_str(&format!("&#{};", c as u32));
    }
    let html_out = decode_chunk(
        &chunk(format!("<config>{html}</config>\n")),
        3,
        false,
        None,
        None,
    );
    let html_ok = html_out.iter().any(|c| c.data.as_ref().contains(aws));

    // C/JS \xNN escapes per byte.
    let mut hx = String::new();
    for b in plain.bytes() {
        hx.push_str(&format!("\\x{b:02x}"));
    }
    let hx_out = decode_chunk(
        &chunk(format!("const blob = \"{hx}\";\n")),
        3,
        false,
        None,
        None,
    );
    let hx_ok = hx_out.iter().any(|c| c.data.as_ref().contains(aws));

    assert!(
        url_ok && html_ok && hx_ok,
        "recall regression: a known-prefix credential wrapped in url/html/escape \
         must still decode through the pipeline (url={url_ok} html={html_ok} \
         x-escape={hx_ok}). The Caesar alphabetic-run gate must be local to \
         the Caesar decoder, NOT a pipeline-wide skip, see the reverted \
         has_decodable_payload at decode/pipeline.rs:95."
    );
}
