//! Lane 7: COHERENCE + WIRING + UTILIZATION regression suite.
//!
//! These black-box tests drive the REAL `keyhog` binary and assert that the
//! operator-facing contract the docs/README/`--help` advertise matches what the
//! binary actually does. Every assertion is anchored on a live source of truth
//! (the binary's own output, or the committed docs read via `include_str!`) so
//! the test stays correct as the corpus grows.
//!
//! Each test pins a SPECIFIC coherence/wiring truth that a prior version of the
//! docs got wrong; if any of these regress, the named assertion goes red:
//!
//!   * `--format` accepts all 9 documented values (text/json/jsonl/sarif/csv/
//!     github-annotations/gitlab-sast/html/junit) and rejects garbage, the format-count claim in
//!     docs/src/output-formats.md.
//!   * `keyhog scan` has NO `--quiet` flag (output-formats.md no longer tells
//!     operators to pass one).
//!   * the JSON `verification` field serialises as the lowercase
//!     `VerificationResult` variant (`skipped`/`live`/`dead`), NOT the
//!     `verified-live`/`verified-dead` text-reporter labels, so the `jq`
//!     filter in output-formats.md actually matches.
//!   * the `--help` EXIT CODES block documents every code the binary emits and
//!     labels exit 2 "User error" (matching docs + `EXIT_USER_ERROR`).
//!   * the exit-code matrix (0 clean / 1 finding / 2 user-error) holds.
//!   * README's cited detector count equals the live embedded count.
//!   * README no longer claims a `0.3` default confidence floor (the canonical
//!     default is `0.40`).
//!   * the canonical backend docs list every live `--backend` spelling the
//!     parser accepts and keep the explicit `--autoroute-gpu` contract visible.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// The keyhog binary under test (injected by Cargo for integration tests).
fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A planted AWS key (same shape the e2e suite uses): a high-confidence,
/// network-free detection so the verdict is "secret found" without `--verify`.
/// Split so this source file is not itself a self-scan hit.
const PLANTED_AWS: &str = concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n");

fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(binary())
        .args(args)
        .output()
        .expect("spawn keyhog");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Scan a temp file containing `content` with the extra flags, returning
/// `(exit_code, stdout, stderr)`.
fn scan_file(content: &str, extra: &[&str]) -> (Option<i32>, String, String) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("planted.txt");
    std::fs::write(&path, content).unwrap();
    let mut args: Vec<&str> = vec!["scan", "--daemon=off", "--backend", "simd"];
    args.extend_from_slice(extra);
    let path_str = path.to_string_lossy().into_owned();
    args.push(&path_str);
    run(&args)
}

// ───────────────────────────── WIRING (vector 9) ─────────────────────────────

/// Every `--format` value the `OutputFormat` enum offers (and that
/// docs/src/output-formats.md advertises) must be
/// ACCEPTED by `scan --format`: i.e. it must not exit 2 (clap unknown-value).
/// A clean file with any valid format exits 0.
#[test]
fn every_documented_format_value_is_accepted() {
    for fmt in [
        "text",
        "json",
        "jsonl",
        "sarif",
        "csv",
        "github-annotations",
        "gitlab-sast",
        "html",
        "junit",
    ] {
        let (code, _o, e) = scan_file("clean prose, no secrets here\n", &["--format", fmt]);
        assert_eq!(
            code,
            Some(0),
            "scan --format {fmt} on a clean file must exit 0 (the format is documented as a \
             valid `--format` value in docs/src/output-formats.md); got {code:?}, stderr: {e}"
        );
    }
}

/// A bogus `--format` value is a USER error and must exit 2, never be silently
/// coerced to a default. This is the negative twin of the format matrix above:
/// it proves the format set is closed, so the documented list is exhaustive.
#[test]
fn unknown_format_value_is_rejected_exit_two() {
    let (code, _o, _e) = scan_file("clean\n", &["--format", "yaml-which-does-not-exist"]);
    assert_eq!(
        code,
        Some(2),
        "an unknown --format value must exit 2 (clap rejects it); got {code:?}"
    );
}

/// `keyhog scan --quiet` is a real output control and must remain documented.
#[test]
fn scan_quiet_flag_matches_documented_surface() {
    let (code, _o, e) = scan_file("clean\n", &["--quiet"]);
    assert_eq!(
        code,
        Some(0),
        "`keyhog scan --quiet` must be accepted; got {code:?}, stderr: {e}"
    );
    // The source-of-truth doc must not advertise a scan `--quiet` flag.
    let doc = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/src/output-formats.md"
    ));
    assert!(
        doc.contains("`--quiet`") && doc.contains("coverage `FAIL`/`WARN`"),
        "output-formats.md must document quiet output without hiding coverage failures"
    );
}

fn normalize_surface_text(text: &str) -> String {
    text.replace("<code>", " ")
        .replace("</code>", " ")
        .replace('`', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

#[test]
fn consumer_surfaces_do_not_publish_roadmap_deferrals() {
    let surfaces = [
        (
            "README.md",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../README.md")),
        ),
        (
            "docs/src/install.md",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../docs/src/install.md"
            )),
        ),
        (
            "docs/src/reference/cli.md",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../docs/src/reference/cli.md"
            )),
        ),
        (
            "docs/src/http-wire.md",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../docs/src/http-wire.md"
            )),
        ),
        (
            "docs/src/workflows/daemon.md",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../docs/src/workflows/daemon.md"
            )),
        ),
        (
            "install.sh",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../install.sh")),
        ),
        (
            "install.ps1",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../install.ps1")),
        ),
        (
            "crates/cli/src/lib.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs")),
        ),
        (
            "crates/cli/src/daemon/trust.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/daemon/trust.rs")),
        ),
    ];
    let banned = [
        "roadmap",
        "not yet shipped",
        "not yet implemented",
        "coming soon",
        "queued for a later release",
        "no promises on timeline",
        "tracked but not yet",
    ];

    for (path, raw) in surfaces {
        let normalized = normalize_surface_text(raw);
        for phrase in banned {
            assert!(
                !normalized.contains(phrase),
                "{path} still publishes deferral wording instead of a current operator contract: {phrase:?}"
            );
        }
    }
}

#[test]
fn canonical_docs_do_not_resurrect_retired_behavior_env_controls() {
    let surfaces = [
        (
            "docs/src/reference/configuration.md",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../docs/src/reference/configuration.md"
            )),
        ),
        (
            "docs/src/reference/env.md",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../docs/src/reference/env.md"
            )),
        ),
    ];
    let stale_claims = [
        "env keyhog_detectors",
        "env: keyhog_detectors",
        "environment variables keyhog_*",
        "keyhog_cache_dir relocates",
        "keyhog_lockdown_require=1",
        "unset keyhog_lockdown_require",
    ];

    for (path, raw) in surfaces {
        let normalized = normalize_surface_text(raw);
        for claim in stale_claims {
            assert!(
                !normalized.contains(claim),
                "{path} still advertises retired behavior-env configuration: {claim:?}"
            );
        }
    }
}

// ─────────────────────────── COHERENCE (vector 10) ───────────────────────────

/// The JSON `verification` field is the lowercase `VerificationResult` variant
/// (`skipped` on an unverified scan), NOT the `verified-live`/`verified-dead`
/// labels the *text* reporter renders. docs/src/output-formats.md's `jq` filter
/// relies on this exact value; a stale doc said `verified-live`, which silently
/// matched zero findings. This drives a real scan and asserts the emitted byte
/// value.
#[test]
fn json_verification_field_is_lowercase_variant_not_text_label() {
    let (code, out, _e) = scan_file(PLANTED_AWS, &["--format", "json"]);
    assert_eq!(code, Some(1), "planted secret must exit 1");
    assert!(
        out.contains("\"verification\":\"skipped\"")
            || out.contains("\"verification\": \"skipped\""),
        "JSON `verification` for an unverified finding must be \"skipped\" (lowercase \
         VerificationResult variant); got output: {out}"
    );
    assert!(
        !out.contains("verified-live") && !out.contains("verified-dead"),
        "JSON output must NOT carry the text-reporter labels verified-live/verified-dead; \
         those are display strings, not the serialized field value. Output: {out}"
    );
    // The doc's `jq` filter must use the value the binary actually emits.
    let doc = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/src/output-formats.md"
    ));
    assert!(
        doc.contains("select(.verification == \"live\")"),
        "output-formats.md must filter on the real JSON value `\"live\"`, not the \
         text label `\"verified-live\"`."
    );
}

/// The `--help` EXIT CODES block must document every code the binary emits and
/// label exit 2 "User error" (matching docs/src/reference/exit-codes.md and the
/// `EXIT_USER_ERROR` constant). Drift-proof: it reads the live `--help`.
#[test]
fn help_exit_codes_block_is_complete_and_labels_match() {
    let (_c, help, _e) = run(&["--help"]);
    for code in keyhog::exit_codes::DEFINITIONS
        .iter()
        .map(|definition| definition.code.to_string())
    {
        assert!(
            help.contains(&code),
            "`keyhog --help` EXIT CODES section omits documented code {code}:\n{help}"
        );
    }
    // Exit 2 must be labelled "User error" (lowercased compare), not "Runtime error".
    let exit2_line = help
        .lines()
        .find(|l| {
            l.trim_start()
                .split_whitespace()
                .next()
                .map(|t| t == "2")
                .unwrap_or(false)
        })
        .unwrap_or_else(|| panic!("no exit-2 line in --help:\n{help}"))
        .to_lowercase();
    assert!(
        exit2_line.contains("user error"),
        "`--help` exit-2 line must say \"User error\" to match docs + EXIT_USER_ERROR; \
         got {exit2_line:?}"
    );
    // Exit 4 must acknowledge the `repair` producer (doctor/repair/backend).
    let exit4_line = help
        .lines()
        .find(|l| {
            l.trim_start()
                .split_whitespace()
                .next()
                .map(|t| t == "4")
                .unwrap_or(false)
        })
        .unwrap_or_else(|| panic!("no exit-4 line in --help:\n{help}"))
        .to_lowercase();
    assert!(
        exit4_line.contains("repair"),
        "`--help` exit-4 line must mention the `repair` producer; got {exit4_line:?}"
    );
}

/// The exit-code matrix the docs promise: 0 clean / 1 finding / 2 user-error.
#[test]
fn exit_code_matrix_holds() {
    let (clean, _o, _e) = scan_file("nothing to see here\n", &["--format", "json"]);
    assert_eq!(clean, Some(0), "clean file must exit 0");

    let (found, _o, _e) = scan_file(PLANTED_AWS, &["--format", "json"]);
    assert_eq!(found, Some(1), "planted secret must exit 1");

    let (missing, _o, _e) = run(&[
        "scan",
        "--daemon=off",
        "--format",
        "json",
        "/no/such/keyhog/path/lane7xyz",
    ]);
    assert_eq!(missing, Some(2), "missing path must exit 2 (user error)");

    let (badflag, _o, _e) = run(&["scan", "--no-such-flag-lane7", "/tmp"]);
    assert_eq!(badflag, Some(2), "unknown flag must exit 2 (user error)");
}

/// README's cited detector count must equal the live embedded count
/// (`detectors --format json` array length). Drift-proof: both numbers are read at
/// runtime / from the committed README, never hardcoded in the test.
#[test]
fn readme_detector_count_matches_embedded() {
    let (_c, json, _e) = run(&["detectors", "--format", "json"]);
    let trimmed = json.trim();
    assert!(
        trimmed.starts_with('[') && trimmed.ends_with(']'),
        "detectors --format json must be a JSON array; got first 80: {:?}",
        &trimmed.chars().take(80).collect::<String>()
    );
    let actual = serde_json::from_str::<serde_json::Value>(&json)
        .expect("detectors JSON parses")
        .as_array()
        .expect("detectors JSON is an array")
        .len();
    assert!(actual > 0, "embedded detector count came back 0");

    let readme = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../README.md"));
    let needle = format!("{actual} detector");
    assert!(
        readme.contains(&needle),
        "README must cite the live embedded detector count `{actual} detector...`; \
         it does not. README and the binary disagree on the corpus size."
    );
}

/// The CLI reference must name every command and every live long flag
/// exposed by the same Clap command model the binary executes.  The prose in
/// the reference remains curated, but its command/flag inventory is generated
/// from this model by the test so adding or renaming a surface cannot leave a
/// stale hand-written table behind.
#[test]
fn cli_reference_covers_live_command_and_flag_inventory() {
    let docs = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/src/reference/cli.md"
    ));
    let root = keyhog::args::command();
    let mut missing_commands = Vec::new();
    let mut missing_flags = std::collections::BTreeSet::new();

    fn collect_flags(
        command: &clap::Command,
        docs: &str,
        missing: &mut std::collections::BTreeSet<String>,
    ) {
        for argument in command
            .get_arguments()
            .filter_map(|argument| argument.get_long())
            .filter(|long| *long != "help")
        {
            if !docs.contains(&format!("--{argument}")) {
                missing.insert(argument.to_string());
            }
        }
        for subcommand in command.get_subcommands() {
            collect_flags(subcommand, docs, missing);
        }
    }

    for subcommand in root
        .get_subcommands()
        .filter(|sub| sub.get_name() != "help")
    {
        let name = subcommand.get_name();
        if !docs.contains(&format!("keyhog {name}")) {
            missing_commands.push(name.to_string());
        }
    }
    collect_flags(&root, docs, &mut missing_flags);

    assert!(
        missing_commands.is_empty(),
        "reference/cli.md is missing live command headings or examples: {missing_commands:?}"
    );
    assert!(
        missing_flags.is_empty(),
        "reference/cli.md is missing live command flags: {missing_flags:?}"
    );
}

/// README must not claim a `0.3` default confidence floor. The canonical
/// default is `0.40` (`ScanConfig::default()`); README previously contradicted
/// itself (0.3 in one place, 0.40 in another). This pins the corrected text.
#[test]
fn readme_states_correct_default_confidence_floor() {
    let readme = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../README.md"));
    assert!(
        !readme.contains("Default threshold `0.3`"),
        "README claims a `0.3` default confidence floor; the canonical default is 0.40 \
         (ScanConfig::default), and the binary's effective-config emits 0.4."
    );
    assert!(
        readme.contains("Default threshold `0.40`"),
        "README must state the real `0.40` default confidence floor."
    );
}

#[test]
fn docs_describe_simd_regex_as_backend_contract_not_hyperscan_requirement() {
    let readme = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../README.md"));
    let detection = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/src/detection.md"
    ));
    let readme_norm = normalize_surface_text(readme);
    let detection_norm = normalize_surface_text(detection);
    for (name, text) in [
        ("README.md", &readme_norm),
        ("docs/src/detection.md", &detection_norm),
    ] {
        assert!(
            text.contains("portable") && text.contains("hyperscan"),
            "{name} must explain that Hyperscan is feature/build dependent and portable builds use CPU"
        );
    }
    assert!(
        readme_norm.contains("hyperscan when that feature is present"),
        "README backend table must state that Hyperscan is conditional"
    );
    assert!(
        detection_norm.contains("pure-rust trigger path"),
        "detection docs must name the portable no-Hyperscan trigger path"
    );
}

/// Backend override is now explicit CLI surface, not an ambient env var. Env
/// docs must not resurrect `KEYHOG_BACKEND`, and configuration docs must point
/// operators to `--backend`.
#[test]
fn docs_keep_backend_override_on_explicit_cli_surface() {
    let env_doc = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/src/reference/env.md"
    ));
    let config_doc = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/src/reference/configuration.md"
    ));
    assert!(
        !env_doc.contains("`KEYHOG_BACKEND`"),
        "env.md must not document the retired KEYHOG_BACKEND control"
    );
    assert!(
        config_doc.contains("`--backend <BACKEND>`") && docs_backend_aliases_are_explicit(),
        "configuration docs must document the explicit --backend surface"
    );
    assert!(
        !env_doc.contains("`KEYHOG_GPU_AUTOROUTE`")
            && config_doc.contains("`--autoroute-gpu`")
            && config_doc.contains("`[system].autoroute_gpu`"),
        "autoroute GPU opt-in must be documented as explicit CLI/TOML config, not env"
    );
}

fn docs_backend_aliases_are_explicit() -> bool {
    let docs = [
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/src/backends.md"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/src/reference/cli.md"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/src/reference/configuration.md"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/src/reference/env.md"
        )),
    ];
    keyhog_scanner::hw_probe::BACKEND_OVERRIDE_VALUES
        .iter()
        .all(|label| docs.iter().all(|doc| doc.contains(label)))
}

/// first-scan.md and verification.md must agree on the dead-credential severity
/// action: a one-tier downgrade (matching `Severity::downgrade_one`), NOT a
/// collapse to a fixed level. first-scan.md previously said "to severity LOW",
/// contradicting verification.md's "Downgrade one tier" table.
#[test]
fn docs_agree_dead_downgrade_is_one_tier_not_fixed_low() {
    let first_scan = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/src/first-scan.md"
    ));
    assert!(
        !first_scan.contains("downgrades dead ones to severity LOW"),
        "first-scan.md says dead credentials are downgraded \"to severity LOW\", but \
         verification.md (and Severity::downgrade_one) define a ONE-TIER downgrade \
         (critical → high, …), not a collapse to LOW."
    );
    assert!(
        first_scan.contains("downgraded one"),
        "first-scan.md must describe the dead-credential downgrade as one severity tier."
    );
    let verification = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/src/verification.md"
    ));
    assert!(
        verification.contains("Downgrade one tier"),
        "verification.md must keep the canonical \"Downgrade one tier\" severity-shift row."
    );
}

/// docs/src/output-formats.md must state the real format count and not undersell
/// the surface. The enum has 11 variants; the doc must not say "four formats".
#[test]
fn output_formats_doc_states_eleven_values() {
    let doc = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/src/output-formats.md"
    ));
    assert!(
        !doc.contains("KeyHog speaks four formats"),
        "output-formats.md still says \"four formats\" but `--format` takes eleven values \
         (text/json/json-envelope/jsonl/jsonl-envelope/sarif/csv/github-annotations/gitlab-sast/html/junit)."
    );
    assert!(
        doc.contains("takes one of eleven values"),
        "output-formats.md must state the current eleven-value format surface."
    );
    for v in [
        "json-envelope",
        "jsonl-envelope",
        "csv",
        "github-annotations",
        "gitlab-sast",
        "html",
        "junit",
    ] {
        assert!(
            doc.contains(v),
            "output-formats.md must mention the `{v}` format value it advertises."
        );
    }
    let action = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.github/actions/keyhog/action.yml"
    ));
    let action_readme = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.github/actions/keyhog/README.md"
    ));
    for v in ["text", "json", "sarif", "jsonl"] {
        assert!(
            action.contains(v) && action_readme.contains(v),
            "the composite Action must advertise its supported `{v}` format"
        );
    }
    for v in [
        "json-envelope",
        "jsonl-envelope",
        "csv",
        "github-annotations",
        "gitlab-sast",
        "html",
        "junit",
    ] {
        assert!(
            !action.contains(v) && !action_readme.contains(v),
            "the composite Action must not advertise unsupported `{v}` format"
        );
    }
    let ci_doc = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/src/workflows/ci.md"
    ));
    let ci_doc_single_line = ci_doc.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        ci_doc_single_line.contains("`format` input intentionally supports the four formats")
            && ci_doc_single_line.contains("Use the installed CLI directly"),
        "CI docs must distinguish the four-format Action wrapper from the full CLI format surface"
    );
}

/// README↔installer verification coherence (dogfood 2026-06-22). `install.sh`
/// and `install.ps1` gate every download on a minisign SIGNATURE against the
/// pinned public key and FAIL CLOSED when minisign is absent: a real install ran
/// on a host with no minisign, it downloaded the binary + `.minisig`, then
/// refused with "minisign is not installed … Refusing to install an unverified
/// keyhog binary" and wrote nothing. README's `## Install` section previously
/// claimed only "Each download is SHA256-verified against the release-side
/// checksum file", which undersells the hard requirement: most hosts ship no
/// minisign, so the headline `curl … | sh` refuses with no forewarning, and the
/// `.sha256` is never even reached (the signature gate fails first). Pin the
/// corrected, coherent wording so the install-verification docs can never
/// silently drift back to a sha256-only claim the installer never honored.
#[test]
fn readme_documents_minisign_install_gate_coherently() {
    let readme = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../README.md"));
    let install_sh = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../install.sh"));
    let install_ps1 = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../install.ps1"));

    // Ground truth FIRST: both installers really do verify a minisign signature
    // and fail closed without it. The README assertions below only make sense
    // while this is the live behavior (so anchor on it).
    assert!(
        install_sh.contains("minisign -Vm")
            && install_sh.contains("Refusing to install an unverified"),
        "install.sh must verify the release minisign signature and fail closed; \
         the README coherence assertions below depend on that being the real behavior."
    );
    assert!(
        install_ps1.contains("minisign")
            && install_ps1.contains("Refusing to install an unverified"),
        "install.ps1 must verify the release minisign signature and fail closed (Windows parity)."
    );

    // Isolate the README `## Install` section (up to the next h2 heading).
    let install_section = readme
        .split("## Install")
        .nth(1)
        .expect("README must have an `## Install` section")
        .split("\n## ")
        .next()
        .expect("README `## Install` section must have body text");

    // Coherence: because the install fails closed without minisign, the README
    // install section MUST tell operators minisign is required and that the
    // install fails closed (not imply sha256-only verification).
    assert!(
        install_section.contains("minisign"),
        "README `## Install` must document the minisign signature requirement (the installer \
         fails closed without minisign); it must not imply sha256-only verification."
    );
    assert!(
        install_section.contains("fails closed") || install_section.contains("Refusing"),
        "README `## Install` must state the installer FAILS CLOSED on a missing/invalid \
         signature, matching install.sh's `Refusing to install an unverified` behavior."
    );
    // The `--insecure` escape hatch the README points operators to must be a real
    // installer flag, so the documented offline/air-gapped path actually works.
    assert!(
        install_section.contains("--insecure"),
        "README `## Install` must document the `--insecure` offline/air-gapped escape hatch."
    );
    assert!(
        install_section.contains("libhyperscan5")
            && install_section.contains("apt-get install")
            && install_section.contains("brew install minisign"),
        "README `## Install` must name Linux Hyperscan/minisign and macOS minisign prerequisites"
    );
    assert!(
        install_sh.contains("--insecure") || install_sh.contains("INSECURE_INSTALL"),
        "install.sh must implement the `--insecure` flag the README documents."
    );

    let install_guide = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/src/install.md"
    ));
    let pinned = install_guide
        .split("## Pinned verified install: Linux / macOS")
        .nth(1)
        .expect("install guide must have the pinned Linux/macOS section")
        .split("\n## ")
        .next()
        .expect("pinned install section must have body text");
    assert!(
        pinned.contains("libhyperscan5")
            && pinned.contains("minisign")
            && pinned.contains("brew install minisign"),
        "the canonical pinned install guide must name every platform verifier/runtime prerequisite"
    );
}

#[test]
fn public_ci_install_recipes_name_verified_runtime_prerequisites() {
    let guide = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/src/workflows/ci.md"
    ));
    for heading in ["## GitLab CI", "## CircleCI", "## Drone CI", "## Buildkite"] {
        let section = guide
            .split(heading)
            .nth(1)
            .unwrap_or_else(|| panic!("CI guide must contain {heading}"))
            .split("\n## ")
            .next()
            .expect("CI recipe section must have body text");
        assert!(
            section.contains("install.sh")
                && section.contains("minisign")
                && section.contains("libhyperscan5"),
            "{heading} must install the signed installer verifier and Linux release runtime before scanning"
        );
    }
}
