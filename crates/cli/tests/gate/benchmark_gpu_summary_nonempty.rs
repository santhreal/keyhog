//! LR1-A8 replacement gate: `benchmark.rs` must report GPU probe text in the
//! exact shape `format_gpu_summary` documents: `unavailable` when no adapter is
//! present, otherwise the adapter name optionally suffixed with ` (NGB)`. This
//! is the string the `keyhog scan --benchmark` `gpu=` header renders.

use keyhog::testing::{CliTestApi as _, API};

#[test]
fn format_gpu_summary_matches_documented_shape() {
    let summary = API.format_gpu_summary();
    assert!(
        !summary.is_empty(),
        "GPU summary must never be the empty string (the no-GPU case is the literal \
         \"unavailable\", not \"\"); got {summary:?}"
    );

    if summary == "unavailable" {
        // No non-software adapter (the documented no-GPU sentinel. Done).
        return;
    }

    // A concrete adapter: the name is non-empty, and any VRAM suffix is the
    // exact ` (NGB)` form (`format!("{} ({}GB)", name, vram_mb/1024)`), never a
    // dangling or malformed parenthesis.
    if let Some(paren) = summary.find(" (") {
        let name = &summary[..paren];
        assert!(
            !name.is_empty(),
            "GPU summary VRAM suffix must follow a non-empty adapter name; got {summary:?}"
        );
        assert!(
            summary.ends_with("GB)"),
            "GPU summary VRAM suffix must be the documented ` (NGB)` form; got {summary:?}"
        );
        let digits = &summary[paren + 2..summary.len() - 3];
        assert!(
            !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()),
            "GPU summary VRAM must be a positive integer count of GB; got {summary:?}"
        );
        assert!(
            digits.parse::<u64>().map(|gb| gb >= 1).unwrap_or(false),
            "GPU summary VRAM must be at least 1GB (the `.max(1)` floor); got {summary:?}"
        );
    } else {
        // Name-only (VRAM unknown): just a non-empty label, no parenthesis.
        assert!(
            !summary.contains('('),
            "name-only GPU summary must carry no parenthesis; got {summary:?}"
        );
    }
}
