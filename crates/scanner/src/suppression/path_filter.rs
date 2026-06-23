//! Path-based suppression predicates. These look only at the source-file
//! path, not the credential value. Used by the api layer to short-circuit
//! whole files (`looks_like_secret_scanner_source`) or whole subdirectories
//! (`looks_like_vendored_minified_path`).

use crate::ascii_ci::{ci_find, contains_path_segment, contains_path_segment_two};

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
    // Avoid the per-match `p.to_ascii_lowercase()` allocation by skimming
    // raw path bytes against pre-lowered needles via `ci_find`. Same
    // ten-needle alternation, zero allocations.
    let bytes = p.as_bytes();
    const NEEDLES: &[&[u8]] = &[
        b"secretscanner",
        b"secret-scanner",
        b"secret_scanner",
        b"credentialscanner",
        b"credential-scanner",
        b"credential_scanner",
        b"trufflehog",
        b"gitleaks",
        b"detect-secrets",
        b"detect_secrets",
    ];
    NEEDLES.iter().any(|n| ci_find(bytes, n))
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
        let basename = crate::platform_compat::path_basename(p);
        let basename_bytes = basename.as_bytes();
        const VENDORED_JS_PREFIXES: &[&[u8]] = &[
            b"bootstrap",
            b"jquery",
            b"react.",
            b"react-",
            b"vue.",
            b"vue-",
            b"angular",
            b"ember",
            b"backbone",
            b"lodash",
            b"underscore",
            b"moment",
            b"alertify",
            b"fullcalendar",
            b"datatables",
            b"highcharts",
            b"chart.",
            b"chart-",
            b"select2",
            b"tinymce",
            b"ckeditor",
            b"codemirror",
            b"html5",
            b"modernizr",
            b"respond",
        ];
        if VENDORED_JS_PREFIXES.iter().any(|prefix| {
            basename_bytes
                .get(..prefix.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
        }) {
            return true;
        }
    }
    false
}

pub(crate) fn path_is_ci_workflow_file(path: Option<&str>) -> bool {
    let Some(p) = path else {
        return false;
    };
    p.contains("/.github/workflows/")
        || p.contains("\\.github\\workflows\\")
        || p.contains("/.github/actions/")
        || p.contains("\\.github\\actions\\")
        || p.contains("/.gitlab-ci.yml")
        || p.contains("\\.gitlab-ci.yml")
        || p.ends_with(".gitlab-ci.yml")
        || p.contains("/.circleci/")
        || p.contains("\\.circleci\\")
        || p.contains("/azure-pipelines")
        || p.contains("\\azure-pipelines")
        || p.contains("/bitbucket-pipelines")
        || p.contains("\\bitbucket-pipelines")
        || p.contains("/.travis.yml")
        || p.contains("\\.travis.yml")
        || p.ends_with(".travis.yml")
        || crate::platform_compat::path_basename(p).eq_ignore_ascii_case("Jenkinsfile")
}

pub(crate) fn path_is_i18n_file(path: Option<&str>) -> bool {
    let Some(p) = path else {
        return false;
    };
    p.contains("/locale/")
        || p.contains("\\locale\\")
        || p.contains("/locales/")
        || p.contains("\\locales\\")
        || p.contains("/i18n/")
        || p.contains("\\i18n\\")
        || p.contains("/l10n/")
        || p.contains("\\l10n\\")
        || p.contains("/translations/")
        || p.contains("\\translations\\")
        || p.contains("/lang/")
        || p.contains("\\lang\\")
        || p.contains("/langs/")
        || p.contains("\\langs\\")
        || p.ends_with(".po")
        || p.ends_with(".pot")
        || {
            let name = p.rsplit(['/', '\\']).next().unwrap_or(p); // LAW10: split yields >=1 element; unwrap_or is the never-taken total default, recall-safe
            (name.starts_with("locale_")
                || name.starts_with("messages_")
                || name.starts_with("strings_"))
                && (name.ends_with(".ini")
                    || name.ends_with(".properties")
                    || name.ends_with(".xml")
                    || name.ends_with(".json")
                    || name.ends_with(".yaml")
                    || name.ends_with(".yml"))
        }
}

pub(crate) fn looks_like_raw_base64_file_path(path: Option<&str>) -> bool {
    raw_base64_path_match(path, true, false)
}

pub(crate) fn looks_like_entropy_raw_base64_file_path(path: Option<&str>) -> bool {
    raw_base64_path_match(path, false, false)
}

pub(crate) fn looks_like_hot_pattern_base64_path(path: Option<&str>) -> bool {
    raw_base64_path_match(path, false, true)
}

fn raw_base64_path_match(
    path: Option<&str>,
    include_plain_base64_txt: bool,
    exclude_structured_config: bool,
) -> bool {
    let Some(p) = path else {
        return false;
    };
    let bytes = p.as_bytes();
    if crate::ascii_ci::ends_with_ignore_ascii_case(bytes, b".b64")
        || crate::ascii_ci::ends_with_ignore_ascii_case(bytes, b".base64")
    {
        return true;
    }
    let basename = crate::platform_compat::path_basename_bytes(bytes);
    if exclude_structured_config
        && (crate::ascii_ci::ends_with_ignore_ascii_case(basename, b".json")
            || crate::ascii_ci::ends_with_ignore_ascii_case(basename, b".yml")
            || crate::ascii_ci::ends_with_ignore_ascii_case(basename, b".yaml"))
    {
        return false;
    }
    crate::ascii_ci::starts_with_ignore_ascii_case(basename, b"base64_")
        || crate::ascii_ci::ci_find(basename, b"base64_string")
        || (include_plain_base64_txt && basename.eq_ignore_ascii_case(b"base64.txt"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_workflow_path_matches_cross_platform_ci_files() {
        assert!(path_is_ci_workflow_file(Some(
            "/repo/.github/workflows/release.yml"
        )));
        assert!(path_is_ci_workflow_file(Some(
            r"C:\repo\.github\actions\setup\action.yml"
        )));
        assert!(path_is_ci_workflow_file(Some("/repo/.gitlab-ci.yml")));
        assert!(path_is_ci_workflow_file(Some(r"C:\repo\Jenkinsfile")));
        assert!(!path_is_ci_workflow_file(Some("/repo/src/Jenkinsfile.txt")));
    }

    #[test]
    fn i18n_path_matches_translation_file_shapes() {
        assert!(path_is_i18n_file(Some("/repo/locale/messages.po")));
        assert!(path_is_i18n_file(Some(r"C:\repo\i18n\strings.json")));
        assert!(path_is_i18n_file(Some(
            "/repo/config/messages_en.properties"
        )));
        assert!(!path_is_i18n_file(Some("/repo/config/messages_en.rs")));
    }

    #[test]
    fn raw_base64_path_policies_preserve_call_site_contracts() {
        assert!(looks_like_raw_base64_file_path(Some(
            "/repo/assets/blob.B64"
        )));
        assert!(looks_like_raw_base64_file_path(Some("/repo/base64.txt")));
        assert!(!looks_like_entropy_raw_base64_file_path(Some(
            "/repo/base64.txt"
        )));
        assert!(looks_like_entropy_raw_base64_file_path(Some(
            "/repo/base64_string.txt"
        )));
        assert!(looks_like_hot_pattern_base64_path(Some(
            r"C:\repo\assets\base64_string.txt"
        )));
        assert!(!looks_like_hot_pattern_base64_path(Some(
            "/repo/base64_string.json"
        )));
    }
}
