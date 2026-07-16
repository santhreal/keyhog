//! Detector-owned credential shape rules.
//!
//! The per-detector shape CONSTRAINT (`exact_length` / `prefix` / `body_*`) is a
//! `keyhog_core::CredentialShape` declared in each detector's own TOML
//! (`[detector.credential_shape]`, DET-0, was the centralized
//! `rules/detector-credential-shapes.toml` `[[shape]]` list keyed by detector id).
//! Core owns the data AND its internal-consistency validation
//! (`CredentialShape::validate`); this module owns the SCANNER side: the compiled
//! [`CredentialShapeRule`] + its per-credential [`CredentialShapeRule::allows`]
//! gate, built per detector from that spec. Because the shape now lives on the
//! detector's own spec, the previous "shape rule for an unknown detector id" class
//! is impossible by construction (no id list, no id validation).

use keyhog_core::{CredentialShape, DetectorSpec};

/// The PEM armor header that opens every `-----BEGIN … PRIVATE KEY-----` block
/// (and X.509 certs). SINGLE OWNER: it is the load-bearing prefix of the
/// `private-key` / `ssh-private-key` / `github-app-private-key` detector
/// patterns, and scanner logic keys off it in two places, the suppression
/// carve-out (a PEM body must NOT be masking-pattern suppressed, or the detector
/// silently misses real OPENSSH keys) and the entropy plausibility gate. Both
/// now read this const via [`is_pem_block`] instead of two bare `"-----BEGIN"`
/// literals free to drift; a guard test binds it to its authoritative detector.
pub(crate) const PEM_BEGIN_MARKER: &str = "-----BEGIN";

/// True when `value` opens a PEM armor block (private key, certificate, …).
/// One predicate so every "is this a PEM body?" decision agrees byte-for-byte.
pub(crate) fn is_pem_block(value: &str) -> bool {
    value.starts_with(PEM_BEGIN_MARKER)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CredentialShapeRule {
    exact_length: Option<usize>,
    prefix: Option<String>,
    body_min_length: Option<usize>,
    body_max_length: Option<usize>,
}

impl CredentialShapeRule {
    pub(crate) fn allows(&self, credential: &str) -> bool {
        if self
            .exact_length
            .is_some_and(|expected| credential.len() != expected)
        {
            return false;
        }

        if let Some(prefix) = self.prefix.as_deref() {
            let Some(body) = credential.strip_prefix(prefix) else {
                return true;
            };
            if self
                .body_min_length
                .is_some_and(|minimum| body.len() < minimum)
            {
                return false;
            }
            if self
                .body_max_length
                .is_some_and(|maximum| body.len() > maximum)
            {
                return false;
            }
        }

        true
    }

    /// Compile the scanner-side gate from a detector's own declared shape
    /// (`DetectorSpec::credential_shape`). The spec is validated separately at
    /// build time (`CredentialShape::validate`); this only maps the fields.
    fn from_spec(shape: &CredentialShape) -> Self {
        Self {
            exact_length: shape.exact_length,
            prefix: shape.prefix.clone(),
            body_min_length: shape.body_min_length,
            body_max_length: shape.body_max_length,
        }
    }

    #[cfg(test)]
    pub(crate) fn exact_length_for_test(exact_length: usize) -> Self {
        Self {
            exact_length: Some(exact_length),
            prefix: None,
            body_min_length: None,
            body_max_length: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn prefix_body_range_for_test(
        prefix: &str,
        body_min_length: usize,
        body_max_length: usize,
    ) -> Self {
        Self {
            exact_length: None,
            prefix: Some(prefix.to_string()),
            body_min_length: Some(body_min_length),
            body_max_length: Some(body_max_length),
        }
    }
}

/// Compile the per-detector credential-shape gate for every detector, indexed to
/// match `detectors`. Each detector's shape comes from its OWN spec
/// (`DetectorSpec::credential_shape`, DET-0), validated fail-closed
/// (`CredentialShape::validate`) so a malformed shape is a build error, never a
/// silent skip. A detector with no `[detector.credential_shape]` maps to `None`
/// (no shape gate). There is no id list and no "unknown detector" case, the
/// shape rides on the detector's own spec, so it cannot name a detector that does
/// not exist.
pub(crate) fn build_detector_shape_rules(
    detectors: &[DetectorSpec],
) -> Result<Vec<Option<CredentialShapeRule>>, String> {
    detectors
        .iter()
        .map(|detector| match &detector.credential_shape {
            None => Ok(None),
            Some(shape) => {
                shape.validate(&detector.id)?;
                Ok(Some(CredentialShapeRule::from_spec(shape)))
            }
        })
        .collect()
}

#[cfg(test)]
#[path = "../tests/unit/credential_shapes.rs"]
mod tests;
