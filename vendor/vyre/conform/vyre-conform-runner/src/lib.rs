//! Conformance test runner + certificate emitter.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![deny(missing_docs)]

pub mod bundle_cert;
pub mod cert;
/// Convergence lens for fixpoint ops (transfer + bitset_fixpoint loop).
pub mod convergence_lens;
/// Shared CPU/GPU floating-point parity helpers used by both
/// `prove` and the parity-matrix test harness.
pub mod fp_parity;
/// Reusable conform lenses (witness / cpu_vs_backend / fixpoint).
pub mod lens {
    pub use vyre_test_harness::lens::{cpu_vs_backend, fixpoint, witness, LensOutcome};
}

pub use bundle_cert::{
    issue_bundle_cert, verify_bundle_against_reference, verify_bundle_with_backend,
    verify_cert_signature_hex, BundleCertError, BundleCertificate, CorpusWitness,
};
pub use cert::{issue_certificate, verify_structural, Certificate, CertificateError, IssueInput};
