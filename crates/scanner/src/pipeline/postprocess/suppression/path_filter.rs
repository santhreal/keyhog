//! Path-based suppression predicates. These look only at the source-file
//! path, not the credential value. Used by the api layer to short-circuit
//! whole files (`looks_like_secret_scanner_source`) or whole subdirectories
//! (`looks_like_vendored_minified_path`).

/// True if the file at `path` is itself a secret-scanner source file.
/// Such files contain detector regex patterns (`/AKIA[A-Z0-9]{16}/g`,
/// `'(?:ASIA|AKIA)[A-Z2-7]{16}'`, `dn_[a-zA-Z0-9_-]{20,}`) that the engine
/// will match against itself - every named detector + hot pattern routinely
/// emits a finding on its own regex DEFINITION. Most of these are caught
/// by `looks_like_regex_literal_tail`, but the unicode-escape / caesar
/// decoders mangle the trailing sigil out of recognition. Skipping the
/// whole file (any source whose path or basename contains a secret-scanner
/// keyword) is safer than playing whack-a-mole with decoder variants.
pub(crate) fn looks_like_secret_scanner_source(path: Option<&str>) -> bool {
    let Some(p) = path else {
        return false;
    };
    let lower = p.to_ascii_lowercase();
    lower.contains("secretscanner")
        || lower.contains("secret-scanner")
        || lower.contains("secret_scanner")
        || lower.contains("credentialscanner")
        || lower.contains("credential-scanner")
        || lower.contains("credential_scanner")
        || lower.contains("trufflehog")
        || lower.contains("gitleaks")
        || lower.contains("detect-secrets")
        || lower.contains("detect_secrets")
}

/// Path-segment substring test that tolerates either `/seg/` (POSIX)
/// or `\seg\` (Windows). Used by the vendored-path gate below so that
/// Windows checkouts (`C:\src\app\node_modules\…`) get the same
/// suppression treatment as POSIX checkouts. No allocations - walks
/// `path` once with `find()`.
fn contains_path_segment(path: &str, segment: &str) -> bool {
    let mut needle_unix = String::with_capacity(segment.len() + 2);
    needle_unix.push('/');
    needle_unix.push_str(segment);
    needle_unix.push('/');
    let mut needle_win = String::with_capacity(segment.len() + 2);
    needle_win.push('\\');
    needle_win.push_str(segment);
    needle_win.push('\\');
    path.contains(needle_unix.as_str()) || path.contains(needle_win.as_str())
}

/// Two-segment variant: matches `/a/b/` (POSIX) or `\a\b\` (Windows).
/// Used for the `public/plugins`, `wp-content/plugins`, etc. matches
/// where both segments must be present in sequence.
fn contains_path_segment_two(path: &str, a: &str, b: &str) -> bool {
    let mut needle_unix = String::with_capacity(a.len() + b.len() + 3);
    needle_unix.push('/');
    needle_unix.push_str(a);
    needle_unix.push('/');
    needle_unix.push_str(b);
    needle_unix.push('/');
    let mut needle_win = String::with_capacity(a.len() + b.len() + 3);
    needle_win.push('\\');
    needle_win.push_str(a);
    needle_win.push('\\');
    needle_win.push_str(b);
    needle_win.push('\\');
    path.contains(needle_unix.as_str()) || path.contains(needle_win.as_str())
}

/// True if `path` looks like a vendored 3rd-party JS/CSS/wasm bundle.
/// These are minified copies of libraries the project does NOT author -
/// any "secret-like" match inside them is a coincidence in the minified
/// byte stream, not a leaked credential.
///
/// Catches:
///   * `gogs/public/plugins/codemirror-5.17.0/mode/dockerfile/dockerfile.js`
///     (`variable-2`/`variable-3` token classes captured as generic-secret)
///   * `gogs/public/plugins/pdfjs-5.2.133/web/wasm/openjpeg_nowasm_fallback.js`
///     (minified WASM glue with `ASIA` random byte sequence triggering
///     `hot-aws_session_key`)
///   * `node_modules/`, `vendor/`, `wp-includes/`, `wp-content/plugins/`
///     (npm / Composer / WordPress vendored trees)
pub(crate) fn looks_like_vendored_minified_path(path: Option<&str>) -> bool {
    let Some(p) = path else {
        return false;
    };
    // Substring-match both POSIX-style (`/dir/`) and Windows-style
    // (`\dir\`) vendored-tree fragments. Without this, every match
    // inside `C:\src\app\node_modules\…` on a Windows checkout would
    // skip the vendored-suppression and surface as a finding -
    // emitting thousands of FPs the moment a Windows user scans a
    // typical Node project. `contains_segment` is path-shape-only;
    // no allocation per call (just byte scans).
    if contains_path_segment(p, "node_modules")
        || contains_path_segment_two(p, "public", "plugins")
        || contains_path_segment_two(p, "public", "static")
        || contains_path_segment_two(p, "public", "vendor")
        || contains_path_segment_two(p, "static", "vendor")
        || contains_path_segment(p, "wp-includes")
        || contains_path_segment_two(p, "wp-content", "plugins")
        || contains_path_segment_two(p, "wp-content", "themes")
        || contains_path_segment(p, "bower_components")
        || contains_path_segment(p, "jspm_packages")
        || contains_path_segment(p, "site-packages")
        || p.contains("/dist/vendor")
        || p.contains("\\dist\\vendor")
        || contains_path_segment_two(p, "dist", "assets")
        || contains_path_segment_two(p, "vendor", "assets")
        || p.ends_with(".min.js")
        || p.ends_with(".bundle.js")
        || p.ends_with(".min.css")
    {
        return true;
    }
    // Rails legacy asset path: `app/assets/javascripts/<name>.js`. First-
    // party Rails JS today lives in `app/javascript/` (Webpacker era) or
    // `app/assets/builds/` (esbuild/Vite era). The `app/assets/javascripts/`
    // directory predominantly holds vendored libraries (bootstrap-*,
    // jquery-*, alertify, datatables, fullcalendar, jsapi). Match the
    // most common vendored filename prefixes.
    if p.contains("/app/assets/javascripts/")
        || p.contains("\\app\\assets\\javascripts\\")
        || p.contains("/vendor/javascripts/")
        || p.contains("\\vendor\\javascripts\\")
    {
        // `rsplit(['/', '\\'])` so Windows-style paths still collapse
        // to the bare filename - the prefix list below would otherwise
        // never match on Windows checkouts.
        let basename = p
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(p)
            .to_ascii_lowercase();
        const VENDORED_JS_PREFIXES: &[&str] = &[
            "bootstrap",
            "jquery",
            "react.",
            "react-",
            "vue.",
            "vue-",
            "angular",
            "ember",
            "backbone",
            "lodash",
            "underscore",
            "moment",
            "alertify",
            "fullcalendar",
            "datatables",
            "highcharts",
            "chart.",
            "chart-",
            "select2",
            "tinymce",
            "ckeditor",
            "codemirror",
            "html5",
            "modernizr",
            "respond",
        ];
        if VENDORED_JS_PREFIXES
            .iter()
            .any(|prefix| basename.starts_with(prefix))
        {
            return true;
        }
    }
    false
}
