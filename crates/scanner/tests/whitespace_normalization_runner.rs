//! Whitespace / BOM / line-ending normalization runner, a credential-
//! sufficient secret survives whitespace transforms applied around it.
//!
//! Real files arrive with a UTF-8 BOM (`EF BB BF`), CRLF or CR-only line
//! endings, tabs for spaces, NBSP between tokens (Word-pasted `.env`), trailing
//! whitespace, and zero-width characters at boundaries (copy-pasted from web
//! docs). All have been observed in actual leaked-secret commits. A correct
//! scanner treats them as semantically equivalent to the canonical positive.
//!
//! BEHAVIOR contract, not an accuracy rate
//! ---------------------------------------
//! Every variant here rewrites whitespace/BOM/line-endings OUTSIDE the
//! credential and never touches the credential bytes, so this is a
//! *credential-sufficiency invariance* contract (see `support::contracts`): a
//! credential that fires on its own bytes alone MUST still surface under every
//! whitespace variant, there is no keyhog policy that suppresses a secret
//! because a BOM or tab sits beside it, so any credential-sufficient miss is a
//! real normalization recall bug. We gate exactly that, all-or-nothing, across
//! every variant. Companion-required positives are recorded but never gated
//! (their context survival is an accuracy RATE owned by the bench, the T-01
//! line this rewrite holds).
//!
//! Byte-preservation is enforced BY CONSTRUCTION: not every credential is
//! whitespace-free (a `KakaoAK <hex>` prefix, a connection-string password with
//! spaces, a PEM block with internal newlines all contain whitespace), so a
//! naive whole-text `replace(' ', "  ")` / `replace('\n', "\r\n")` would mutate
//! the credential itself, a different secret, not a normalization miss. We
//! therefore apply each variant ONLY to the bytes before and after the
//! credential span (exactly as `unicode_confusable_runner` swaps only companion
//! context), leaving the credential verbatim. The credential-sufficiency
//! invariance is sound precisely because the transform is credential-preserving;
//! see the Screwdriver Principle's soundness oracle in CLAUDE.md.

mod support;
use support::contracts::{
    load_contracts, make_chunk, primaries, scanner, sufficiency_mask, surfaces, Primary,
};

const SOURCE_TYPE: &str = "whitespace-normalization";

#[derive(Debug, Clone, Copy)]
enum Variant {
    Baseline,
    Crlf,
    CrOnly,
    Bom,
    BomCrlf,
    LeadingNbsp,
    TrailingWhitespace,
    TabsForSpaces,
    DoubleSpaces,
    /// ZWSP/ZWJ inserted at line boundaries OUTSIDE the credential, must not
    /// affect detection. (Inside-credential zero-width chars are a separate
    /// question owned by `unicode_confusable_runner`.)
    ZwspBoundary,
}

impl Variant {
    const ALL: &'static [Variant] = &[
        Variant::Baseline,
        Variant::Crlf,
        Variant::CrOnly,
        Variant::Bom,
        Variant::BomCrlf,
        Variant::LeadingNbsp,
        Variant::TrailingWhitespace,
        Variant::TabsForSpaces,
        Variant::DoubleSpaces,
        Variant::ZwspBoundary,
    ];

    fn label(self) -> &'static str {
        match self {
            Variant::Baseline => "baseline",
            Variant::Crlf => "crlf",
            Variant::CrOnly => "cr-only",
            Variant::Bom => "bom",
            Variant::BomCrlf => "bom-crlf",
            Variant::LeadingNbsp => "leading-nbsp",
            Variant::TrailingWhitespace => "trailing-whitespace",
            Variant::TabsForSpaces => "tabs-for-spaces",
            Variant::DoubleSpaces => "double-spaces",
            Variant::ZwspBoundary => "zwsp-boundary",
        }
    }

    /// Per-segment whitespace transform applied to the bytes BEFORE and AFTER
    /// the credential span only, it never sees the credential bytes, so
    /// byte-preservation holds by construction (see the module header). Line-
    /// based variants use `split_inclusive('\n')` so the segment's own line
    /// endings and any trailing newline are preserved verbatim (the old
    /// `.lines().join("\n")` silently normalized CR/CRLF and dropped a final
    /// newline (a transform we did not intend)).
    fn transform_segment(self, seg: &str) -> String {
        match self {
            Variant::Baseline | Variant::Bom | Variant::LeadingNbsp => seg.to_string(),
            Variant::Crlf | Variant::BomCrlf => seg.replace('\n', "\r\n"),
            Variant::CrOnly => seg.replace('\n', "\r"),
            Variant::TrailingWhitespace => seg
                .split_inclusive('\n')
                .map(|l| match l.strip_suffix('\n') {
                    Some(body) => format!("{body}   \t  \t\n"),
                    None => format!("{l}   \t  \t"),
                })
                .collect(),
            Variant::TabsForSpaces => seg.replace("  ", "\t").replace("   ", "\t\t"),
            Variant::DoubleSpaces => seg.replace(' ', "  "),
            Variant::ZwspBoundary => seg
                .split_inclusive('\n')
                .map(|l| match l.strip_suffix('\n') {
                    Some(body) => format!("\u{200B}{body}\u{200B}\n"),
                    None => format!("\u{200B}{l}\u{200B}"),
                })
                .collect(),
        }
    }

    /// Document-level prefix prepended once to the whole text (BOM, leading
    /// NBSP). These sit at byte 0, never inside the credential, so they need no
    /// span-awareness.
    fn doc_prefix(self) -> &'static str {
        match self {
            Variant::Bom | Variant::BomCrlf => "\u{FEFF}",
            Variant::LeadingNbsp => "\u{00A0}",
            _ => "",
        }
    }

    /// Apply the variant to everything EXCEPT the credential span, leaving the
    /// credential bytes verbatim. A primary whose credential is not a substring
    /// of its own positive text is a fixture invariant violation, surfaced
    /// loudly (CLAUDE.md Law 10) rather than silently whole-text transformed.
    fn apply_around(self, text: &str, cred: &str) -> String {
        let pos = text.find(cred).unwrap_or_else(|| {
            panic!(
                "fixture invariant violated: credential {cred:?} is not a substring of its own \
                 positive text, a credential-preserving whitespace variant cannot be located"
            )
        });
        let prefix = self.transform_segment(&text[..pos]);
        let suffix = self.transform_segment(&text[pos + cred.len()..]);
        format!("{}{prefix}{cred}{suffix}", self.doc_prefix())
    }
}

#[test]
fn credential_sufficient_secrets_survive_whitespace_variants() {
    let scanner = scanner();
    let contracts = load_contracts();
    let primaries: Vec<Primary> = primaries(&contracts);
    let sufficient = sufficiency_mask(&scanner, SOURCE_TYPE, &primaries);
    let n_sufficient = sufficient.iter().filter(|b| **b).count();

    let mut gated_assertions = 0usize;
    let mut gated_hits = 0usize;
    let mut violations: Vec<String> = Vec::new();

    // Gate: every credential-sufficient primary must survive EVERY whitespace
    // variant applied around it. All-or-nothing (no rate).
    for (idx, p) in primaries.iter().enumerate() {
        if !sufficient[idx] {
            continue;
        }
        for variant in Variant::ALL {
            let text = variant.apply_around(&p.text, &p.credential);
            let chunk = make_chunk(&text, SOURCE_TYPE, "normalized.txt");
            gated_assertions += 1;
            if surfaces(&scanner, &chunk, &p.credential) {
                gated_hits += 1;
            } else {
                violations.push(format!(
                    "{detector} :: variant={variant} :: standalone-firing credential {cred:?} \
                     DROPPED under this whitespace variant",
                    detector = p.detector_id,
                    variant = variant.label(),
                    cred = p.credential,
                ));
            }
        }
    }

    // Companion-required corpus context, counted ONCE at baseline. Their
    // per-variant survival is a bench-owned RATE, never computed here (T-01)
    // matching `line_length_runner`'s baseline-only companion treatment.
    let mut companion_runs = 0usize;
    let mut companion_hits = 0usize;
    for (idx, p) in primaries.iter().enumerate() {
        if sufficient[idx] {
            continue;
        }
        companion_runs += 1;
        let text = Variant::Baseline.apply_around(&p.text, &p.credential);
        let chunk = make_chunk(&text, SOURCE_TYPE, "normalized.txt");
        if surfaces(&scanner, &chunk, &p.credential) {
            companion_hits += 1;
        }
    }

    eprintln!(
        "whitespace-normalization: {n_sufficient}/{} primaries fire standalone; gated survival \
         {gated_hits}/{gated_assertions} (must be 100%) across {} variants. companion-required \
         baseline: {companion_hits}/{companion_runs} fire at baseline (informational; per-variant \
         survival is a bench RATE).",
        primaries.len(),
        Variant::ALL.len(),
    );

    assert!(
        violations.is_empty(),
        "whitespace-normalization credential-sufficiency invariance violated ({} cases): a \
         credential that fires standalone was dropped when a whitespace/BOM/line-ending variant \
         was applied around it, a normalization recall bug, NOT a fixture artifact:\n  - {}",
        violations.len(),
        violations.join("\n  - "),
    );
}
