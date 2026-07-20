//! Target specification for candidate-generation recall.
//!
//! ## Contract
//! This suite pins prefix-free secret shapes that depend on candidate generation
//! rather than a vendor detector. Named detectors anchor on service syntax;
//! generic hex keys, encoded secrets, alternate JWT headers, URL credentials,
//! and connection-string passwords require the generic production paths.
//!
//! This file is the executable form of that gap: a table of representative
//! secret shapes modeled on the classes in CredData's missed positives
//! (keyword-anchored `hex32/48/64`, raw `base64`, header-order JWTs,
//! URL-embedded credentials, and connection-string passwords), each written as
//! a line an operator could encounter. Every case asserts that the scanner
//! surfaces the exact secret value.
//!
//! These are NOT vendor-prefixed tokens (those already work and are covered by
//! the detector self-validation suite); every fixture is deliberately
//! prefix-free so a green can ONLY come from real generation work, never from a
//! service-signature shortcut. None of these literals carry a real provider
//! checksum, so they exercise the generic keyword/shape path exclusively.
//!
//! Do NOT weaken these (Law 9): a target spec pins what keyhog owes, not what it
//! has. If a shape is a deliberate non-target (a true negative we must not fire
//! on), it belongs in a precision test, not here. The literals below are
//! synthetic and fixed; none is a live credential.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

/// Build the shipped detector set + compiled scanner once (shared by every
/// case via a process-local `OnceLock` so the table pays one compile).
fn scanner() -> &'static CompiledScanner {
    use std::sync::OnceLock;
    static S: OnceLock<CompiledScanner> = OnceLock::new();
    S.get_or_init(|| {
        let detectors =
            keyhog_core::load_detectors(&detector_dir()).expect("load shipped detectors");
        CompiledScanner::compile(detectors).expect("compile shipped scanner")
    })
}

/// Scan one source line through BOTH production backends (SIMD/CPU prefilter and
/// the CPU fallback where the keyword bridge runs) and return every captured
/// credential string. A value is "surfaced" if EITHER backend emits it, the
/// operator path picks a backend per host, so a recall target is met only if the
/// value is reachable on the path that host would take.
fn credentials_for(line: &str) -> Vec<String> {
    let s = scanner();
    let chunk = Chunk {
        data: line.into(),
        metadata: ChunkMetadata::default(),
    };
    let mut out = Vec::new();
    for backend in [ScanBackend::SimdCpu, ScanBackend::CpuFallback] {
        s.clear_fragment_cache();
        for m in s
            .scan_chunks_with_backend(std::slice::from_ref(&chunk), backend)
            .into_iter()
            .flatten()
        {
            out.push(m.credential.as_str().to_string());
        }
    }
    out
}

/// True if the scanner surfaced a credential whose captured value overlaps
/// `value` (either contains the other), the SAME containment rule the CredData
/// leaderboard scorer (`bench.score.overlap`) uses to attribute a true positive,
/// so a green here is bit-faithful to a leaderboard recall hit.
fn surfaces(line: &str, value: &str) -> bool {
    credentials_for(line)
        .iter()
        .any(|c| c.contains(value) || value.contains(c.as_str()))
}

/// One worklist row: a human-readable name, the committed source line, and the
/// exact secret value the scanner must surface from it.
struct MissCase {
    name: &'static str,
    line: &'static str,
    value: &'static str,
}

/// The generation-gap table. Every row is a real-world credential shape that
/// dominates CredData's missed positives; every row is prefix-free so only real
/// keyword/shape generation can satisfy it. Grouped by miss-class so a per-class
/// failure count is legible in the run output.
const MISS_TABLE: &[MissCase] = &[
    // ── keyword-anchored hex keys (canonical AES/HMAC lengths) ──────────
    MissCase {
        name: "hex32_api_key_assign",
        line: "api_key = \"3f8a9c2e1b7d4f6a8c0e2d4f6a8b0c1e\"",
        value: "3f8a9c2e1b7d4f6a8c0e2d4f6a8b0c1e",
    },
    MissCase {
        name: "hex48_encryption_key_assign",
        line: "encryption_key: 021b5eb43337a4bb765b5f3f9176172f5f3afedc863385fc",
        value: "021b5eb43337a4bb765b5f3f9176172f5f3afedc863385fc",
    },
    MissCase {
        name: "hex64_secret_key_assign",
        line: "SECRET_KEY=25eef8a17c7aa607017b85e88a3a9e80099b5adaaba772299bc0086458bd2ad6",
        value: "25eef8a17c7aa607017b85e88a3a9e80099b5adaaba772299bc0086458bd2ad6",
    },
    MissCase {
        name: "hex64_signing_key_json",
        line: "  \"signing_key\": \"450fa13c33e0cb0ed96248f7563b11150d1bc15ddba9c0ca02e8ad0faf33389f\",",
        value: "450fa13c33e0cb0ed96248f7563b11150d1bc15ddba9c0ca02e8ad0faf33389f",
    },
    MissCase {
        name: "hex32_client_secret_yaml",
        line: "client_secret: 7d4f6a8b0c1e3f8a9c2e1b7d4f6a8b0c",
        value: "7d4f6a8b0c1e3f8a9c2e1b7d4f6a8b0c",
    },
    MissCase {
        name: "hex64_master_key_env",
        line: "MASTER_KEY=92c127dc993be1698acd9ab128bab778f22370eed5c4ca20bcce9f653e5541c1",
        value: "92c127dc993be1698acd9ab128bab778f22370eed5c4ca20bcce9f653e5541c1",
    },
    // ── keyword-anchored raw base64 secrets (no vendor prefix) ──────────
    MissCase {
        name: "base64_secret_assign",
        line: "secret = \"aGVsbG8td29ybGQtdGhpcy1pcy1hLXNlY3JldC12YWx1ZQ==\"",
        value: "aGVsbG8td29ybGQtdGhpcy1pcy1hLXNlY3JldC12YWx1ZQ==",
    },
    MissCase {
        name: "base64_password_yaml",
        line: "password: U3VwZXJTZWNyZXRQYXNzd29yZDEyMzQ1Njc4OTA=",
        value: "U3VwZXJTZWNyZXRQYXNzd29yZDEyMzQ1Njc4OTA=",
    },
    MissCase {
        name: "base64_auth_token_env",
        line: "AUTH_TOKEN=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG0=",
        value: "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG0=",
    },
    MissCase {
        name: "base64url_api_secret_json",
        line: "  \"api_secret\": \"dGhpcy1pcy1hLWJhc2U2NHVybC1lbmNvZGVkLXNlY3JldA\",",
        value: "dGhpcy1pcy1hLWJhc2U2NHVybC1lbmNvZGVkLXNlY3JldA",
    },
    MissCase {
        name: "k8s_data_base64_secret",
        line: "  api-key: c3VwZXItc2VjcmV0LWt1YmVybmV0ZXMtYXBpLWtleS12YWx1ZQ==",
        value: "c3VwZXItc2VjcmV0LWt1YmVybmV0ZXMtYXBpLWtleS12YWx1ZQ==",
    },
    // ── JWTs the prefix-anchored detector misses (header field order) ───
    MissCase {
        // header `{"typ":"JWT","alg":"HS256"}` -> starts eyJ0eXAi, NOT eyJhbGci
        name: "jwt_typ_first_header",
        line: "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        value: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    },
    MissCase {
        // header `{"kid":"k1","alg":"RS256"}` -> starts eyJraWQi, NOT eyJhbGci
        name: "jwt_kid_first_header",
        line: "jwt = \"eyJraWQiOiJrMSIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJleGFtcGxlIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\"",
        value: "eyJraWQiOiJrMSIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJleGFtcGxlIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    },
    MissCase {
        // header `{"jwk":{...},"alg":"ES256"}` -> starts eyJqd2si
        name: "jwt_jwk_first_header",
        line: "id_token=eyJqd2siOnt9LCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJjbGllbnQifQ.MEUCIQDx7fK9L2pR4wXc7dF1gH0aZt5nB8jY3hK6mQ9vL2pR4wIgK6mQ9vL2pR4wXc7dF1gH0aZt5nB8jY3hK6mQ9vL2pR4",
        value: "eyJqd2siOnt9LCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJjbGllbnQifQ.MEUCIQDx7fK9L2pR4wXc7dF1gH0aZt5nB8jY3hK6mQ9vL2pR4wIgK6mQ9vL2pR4wXc7dF1gH0aZt5nB8jY3hK6mQ9vL2pR4",
    },
    // ── URL-embedded / connection-string credentials ────────────────────
    MissCase {
        name: "url_basic_auth_userinfo",
        line: "DATABASE_URL=postgres://dbadmin:Xy7pQ2mLrV9wTzKa@db.internal.example.com:5432/prod",
        value: "Xy7pQ2mLrV9wTzKa",
    },
    MissCase {
        name: "mongodb_srv_password",
        line: "mongodb+srv://svc_user:9fK2mWq7Lp4Rz1Tx@cluster0.abcde.mongodb.net/app",
        value: "9fK2mWq7Lp4Rz1Tx",
    },
    MissCase {
        name: "amqp_url_password",
        line: "broker_url = \"amqp://worker:Qz8Wn3Vk6Tp2Lm5R@rabbit.svc.cluster.local:5672/\"",
        value: "Qz8Wn3Vk6Tp2Lm5R",
    },
    MissCase {
        name: "redis_url_password",
        line: "REDIS_URL=redis://:Tp2Lm5RQz8Wn3Vk6@cache.internal:6379/0",
        value: "Tp2Lm5RQz8Wn3Vk6",
    },
    // ── HTTP Authorization headers (non-vendor) ─────────────────────────
    MissCase {
        name: "basic_authorization_b64",
        line: "Authorization: Basic YWRtaW46U3VwM3JTM2NyM3RQNHNzdzByZA==",
        value: "YWRtaW46U3VwM3JTM2NyM3RQNHNzdzByZA==",
    },
    MissCase {
        name: "bearer_opaque_token",
        line: "Authorization: Bearer a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
        value: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
    },
    MissCase {
        name: "x_api_key_header_hex",
        line: "X-Api-Key: 6d4a20f7c9f2c7a14e0b8d63549af1c2",
        value: "6d4a20f7c9f2c7a14e0b8d63549af1c2",
    },
    // ── keyword-anchored high-entropy alphanumeric (no fixed length) ────
    MissCase {
        name: "alnum_password_assign",
        line: "password = \"Kx9mQ2vL7pR4wZ1tN8jB3hY6\"",
        value: "Kx9mQ2vL7pR4wZ1tN8jB3hY6",
    },
    MissCase {
        name: "alnum_access_token_yaml",
        line: "access_token: Zt5nB8jY3hK6mQ9vL2pR4wXc7dF1gH0a",
        value: "Zt5nB8jY3hK6mQ9vL2pR4wXc7dF1gH0a",
    },
    MissCase {
        name: "alnum_private_key_env",
        line: "PRIVATE_KEY=wXc7dF1gH0aZt5nB8jY3hK6mQ9vL2pR4",
        value: "wXc7dF1gH0aZt5nB8jY3hK6mQ9vL2pR4",
    },
    MissCase {
        name: "alnum_credential_json",
        line: "  \"credential\": \"mQ9vL2pR4wXc7dF1gH0aZt5nB8jY3hK6\"",
        value: "mQ9vL2pR4wXc7dF1gH0aZt5nB8jY3hK6",
    },
    MissCase {
        name: "alnum_passwd_ini",
        line: "passwd=R4wXc7dF1gH0aZt5nB8jY3hK6mQ9vL2p",
        value: "R4wXc7dF1gH0aZt5nB8jY3hK6mQ9vL2p",
    },
    MissCase {
        name: "alnum_secret_token_toml",
        line: "secret_token = \"H0aZt5nB8jY3hK6mQ9vL2pR4wXc7dF1g\"",
        value: "H0aZt5nB8jY3hK6mQ9vL2pR4wXc7dF1g",
    },
    // ── batch 2: additional real-world prefix-free shapes (same classes) ─
    // Each is a distinct file-format / keyword / casing variant a human commits;
    // none carries a vendor prefix, so a green can only come from generation.
    MissCase {
        name: "hex32_secret_key_dotenv_lower",
        line: "secret_key=2e1b7d4f6a8b0c1e3f8a9c2e1b7d4f6a",
        value: "2e1b7d4f6a8b0c1e3f8a9c2e1b7d4f6a",
    },
    MissCase {
        name: "hex48_app_secret_properties",
        line: "app.secret=c3c3d7cab79268cb7e2354cc83d29b0fea84e049126e3121",
        value: "c3c3d7cab79268cb7e2354cc83d29b0fea84e049126e3121",
    },
    MissCase {
        name: "hex64_hmac_secret_toml",
        line: "hmac_secret = \"25eef8a17c7aa607017b85e88a3a9e80099b5adaaba772299bc0086458bd2ad6\"",
        value: "25eef8a17c7aa607017b85e88a3a9e80099b5adaaba772299bc0086458bd2ad6",
    },
    MissCase {
        name: "hex64_db_encryption_key_xml",
        line: "  <encryptionKey>450fa13c33e0cb0ed96248f7563b11150d1bc15ddba9c0ca02e8ad0faf33389f</encryptionKey>",
        value: "450fa13c33e0cb0ed96248f7563b11150d1bc15ddba9c0ca02e8ad0faf33389f",
    },
    MissCase {
        name: "hex48_webhook_secret_assign",
        line: "WEBHOOK_SECRET=4d5e6f7081a2b3c4d5e6f7081a2b3c4d5e6f7081a2b3c4d5",
        value: "4d5e6f7081a2b3c4d5e6f7081a2b3c4d5e6f7081a2b3c4d5",
    },
    MissCase {
        name: "base64_private_key_assign",
        line: "private_key = \"cHJpdmF0ZS1rZXktbWF0ZXJpYWwtYmFzZTY0LWVuY29kZWQtdmFsdWU=\"",
        value: "cHJpdmF0ZS1rZXktbWF0ZXJpYWwtYmFzZTY0LWVuY29kZWQtdmFsdWU=",
    },
    MissCase {
        name: "base64_session_secret_yaml",
        line: "session_secret: c2Vzc2lvbi1zZWNyZXQtcmFuZG9tLWJhc2U2NC1ieXRlcw==",
        value: "c2Vzc2lvbi1zZWNyZXQtcmFuZG9tLWJhc2U2NC1ieXRlcw==",
    },
    MissCase {
        name: "base64_signing_secret_env",
        line: "SIGNING_SECRET=c2lnbmluZy1zZWNyZXQta2V5LW1hdGVyaWFsLXJhbmRvbS1ieXRlcw==",
        value: "c2lnbmluZy1zZWNyZXQta2V5LW1hdGVyaWFsLXJhbmRvbS1ieXRlcw==",
    },
    MissCase {
        name: "base64url_refresh_token_json",
        line: "  \"refresh_token\": \"cmVmcmVzaC10b2tlbi1iYXNlNjR1cmwtbm9wYWQtdmFsdWU\",",
        value: "cmVmcmVzaC10b2tlbi1iYXNlNjR1cmwtbm9wYWQtdmFsdWU",
    },
    MissCase {
        // header `{"cty":"JWT","alg":"none"}` -> starts eyJjdHki, NOT eyJhbGci
        name: "jwt_cty_first_header",
        line: "session = eyJjdHkiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1aWQiOiJhYmMxMjMifQ.c2lnbmF0dXJlLXBsYWNlaG9sZGVyLXZhbHVlLWZvci10ZXN0",
        value: "eyJjdHkiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1aWQiOiJhYmMxMjMifQ.c2lnbmF0dXJlLXBsYWNlaG9sZGVyLXZhbHVlLWZvci10ZXN0",
    },
    MissCase {
        // header `{"enc":"A256GCM","alg":"dir"}` -> starts eyJlbmMi, NOT eyJhbGci
        name: "jwt_enc_first_header",
        line: "id_token=eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiZGlyIn0.eyJzdWIiOiJ1c2VyIn0.YW5vdGhlci1zaWduYXR1cmUtcGxhY2Vob2xkZXItdmFsdWU",
        value: "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiZGlyIn0.eyJzdWIiOiJ1c2VyIn0.YW5vdGhlci1zaWduYXR1cmUtcGxhY2Vob2xkZXItdmFsdWU",
    },
    MissCase {
        name: "mysql_url_password",
        line: "JDBC_URL=jdbc:mysql://appuser:Lm5RQz8Wn3Vk6Tp2@mysql.internal:3306/appdb",
        value: "Lm5RQz8Wn3Vk6Tp2",
    },
    MissCase {
        name: "https_userinfo_token",
        line: "git remote add origin https://x-token-auth:Vk6Tp2Lm5RQz8Wn3@bitbucket.org/team/repo.git",
        value: "Vk6Tp2Lm5RQz8Wn3",
    },
    MissCase {
        name: "alnum_refresh_token_assign",
        line: "refresh_token = \"Q9vL2pR4wXc7dF1gH0aZt5nB8jY3hK6m\"",
        value: "Q9vL2pR4wXc7dF1gH0aZt5nB8jY3hK6m",
    },
    MissCase {
        name: "alnum_session_token_yaml",
        line: "session_token: jY3hK6mQ9vL2pR4wXc7dF1gH0aZt5nB8",
        value: "jY3hK6mQ9vL2pR4wXc7dF1gH0aZt5nB8",
    },
    MissCase {
        name: "alnum_auth_key_env",
        line: "AUTH_KEY=dF1gH0aZt5nB8jY3hK6mQ9vL2pR4wXc7",
        value: "dF1gH0aZt5nB8jY3hK6mQ9vL2pR4wXc7",
    },
    MissCase {
        name: "alnum_api_token_ini",
        line: "api_token=gH0aZt5nB8jY3hK6mQ9vL2pR4wXc7dF1",
        value: "gH0aZt5nB8jY3hK6mQ9vL2pR4wXc7dF1",
    },
    MissCase {
        name: "alnum_encryption_secret_toml",
        line: "encryption_secret = \"Zt5nB8jY3hK6mQ9vL2pR4wXc7dF1gH0a\"",
        value: "Zt5nB8jY3hK6mQ9vL2pR4wXc7dF1gH0a",
    },
    MissCase {
        name: "hmac_seed_hex_assign",
        line: "hmac_seed = \"fc090a8d8f282d1221cb1c110c026b4f\"",
        value: "fc090a8d8f282d1221cb1c110c026b4f",
    },
];

/// Sanity invariant: the worklist retains its established minimum so the
/// per-class red count this lane is accountable for cannot silently shrink.
#[test]
fn miss_table_meets_minimum_worklist_size() {
    assert!(
        MISS_TABLE.len() >= 30,
        "generation-gap worklist shrank to {} rows; a missed shape was removed \
         without closing it (Law 9), keep every real-world miss tracked",
        MISS_TABLE.len()
    );
}

#[test]
fn generic_uuid_assignments_remain_identifiers() {
    // Mirror evidence contains hundreds of UUID/resource-UID negatives and no
    // UUID positives. A generic keyword supplies no provider syntax capable of
    // distinguishing the two, so these former recall targets are precision
    // negatives. Provider-specific UUID credentials belong in detector TOMLs.
    for (line, value) in [
        (
            "token = \"3b241101-e2bb-4255-8caf-4136c566a962\"",
            "3b241101-e2bb-4255-8caf-4136c566a962",
        ),
        (
            "api_key: 1f7b3d29-5c8e-4a06-b2d1-9e3f7a0c4b85",
            "1f7b3d29-5c8e-4a06-b2d1-9e3f7a0c4b85",
        ),
        (
            "CLIENT_SECRET=9e3f7a0c-4b85-1f7b-3d29-5c8e4a06b2d1",
            "9e3f7a0c-4b85-1f7b-3d29-5c8e4a06b2d1",
        ),
    ] {
        assert!(
            !surfaces(line, value),
            "generic UUID identifier must not surface: {line}"
        );
    }
}

#[test]
fn bearer_authorization_makes_uuid_shaped_material_a_credential() {
    let value = "b2d19e3f-7a0c-4b85-1f7b-3d295c8e4a06";
    assert!(
        surfaces(&format!("Authorization: Bearer {value}"), value),
        "the structural Bearer anchor owns credential classification even when the value is UUID-shaped"
    );
}

#[test]
fn public_salts_and_nonces_are_not_generic_secrets() {
    for (line, value) in [
        (
            "salt = \"e7c1b4a9d2f60358e7c1b4a9d2f60358\"",
            "e7c1b4a9d2f60358e7c1b4a9d2f60358",
        ),
        (
            "nonce: 0358e7c1b4a9d2f60358e7c1b4a9d2f6",
            "0358e7c1b4a9d2f60358e7c1b4a9d2f6",
        ),
        (
            "password_salt=b4a9d2f60358e7c1b4a9d2f60358e7c1b4a9d2f60358e7c1b4a9d2f60358e7c1",
            "b4a9d2f60358e7c1b4a9d2f60358e7c1b4a9d2f60358e7c1b4a9d2f60358e7c1",
        ),
    ] {
        assert!(
            !surfaces(line, value),
            "generic public salt/nonce must not surface: {line}"
        );
    }
}

#[test]
fn broad_api_key_does_not_reclassify_sha256_as_key_material() {
    let value = "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7c1a49e27e4d6c2";
    assert!(
        !surfaces(&format!("api_key = \"{value}\""), value),
        "64-hex needs an explicit cryptographic-key role; broad api_key remains digest-shaped"
    );
}

#[test]
fn cryptographic_xml_assignment_extracts_its_value() {
    let value = "450fa13c33e0cb0ed96248f7563b11150d1bc15ddba9c0ca02e8ad0faf33389f";
    let line = format!("<encryptionKey>{value}</encryptionKey>");
    assert_eq!(
        keyhog_scanner::testing::entropy_keywords::xml_assignment_value(&line).as_deref(),
        Some(value)
    );
    assert!(
        keyhog_scanner::testing::normalized_assignment_keyword_is_credential_for_test(
            "encryptionkey"
        )
    );
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detector policy");
    let detector = detectors
        .iter()
        .find(|detector| detector.id == "generic-api-key")
        .expect("generic-api-key detector");
    assert!(detector.allows_canonical_hex_key_material("encryptionkey", value));
    let context =
        keyhog_scanner::testing::entropy_scanner::credential_keyword_context("encryptionkey");
    assert!(
        keyhog_scanner::testing::entropy_scanner::candidate_is_plausible(
            value,
            keyhog_scanner::testing::shannon_entropy_scalar_for_test(value.as_bytes()),
            &context,
            &[],
        )
    );
    let credentials = credentials_for(&line);
    assert!(
        credentials
            .iter()
            .any(|credential| credential.contains(value) || value.contains(credential)),
        "XML value extracted but not reported; credentials={credentials:?}"
    );
}

#[test]
fn canonical_hex_repeat_gate_only_rejects_degenerate_material() {
    let random_with_short_run = "450fa13c33e0cb0ed96248f7563b11150d1bc15ddba9c0ca02e8ad0faf33389f";
    assert!(
        surfaces(
            &format!("<encryptionKey>{random_with_short_run}</encryptionKey>"),
            random_with_short_run
        ),
        "short repeats occur naturally in random hex key material"
    );

    let degenerate = "450fa13c33e0cb0ed96248f7563000000000015ddba9c0ca02e8ad0faf33389f";
    assert!(
        !surfaces(&format!("encryption_key={degenerate}"), degenerate),
        "ten identical bytes are synthetic filler, not canonical key material"
    );
}

/// The per-case contract: one exact assertion per prefix-free secret shape. A
/// single test reports every missing candidate so failures retain their class
/// and fixture names.
#[test]
fn every_real_world_secret_shape_is_surfaced() {
    let mut missed: Vec<&str> = Vec::new();
    for case in MISS_TABLE {
        if !surfaces(case.line, case.value) {
            missed.push(case.name);
        }
    }
    assert!(
        missed.is_empty(),
        "GENERATION GAP: {} of {} real-world secret shapes are NOT surfaced by \
         the shipped scanner (no candidate generated for the prefix-free value). \
         Each is a tracked recall miss until keyword/shape generation lands:\n  {}",
        missed.len(),
        MISS_TABLE.len(),
        missed.join("\n  ")
    );
}

// ── per-class roll-up assertions ───────────────────────────────────────
// Distinct from the table enumerator, these name the affected class so a
// systemic generation failure is not reduced to scattered case failures. Each
// asserts the class recall over its table rows
// meets the SAME floor the CredData target spec (`test_recall_targets.py`) sets,
// keeping the Rust micro-target and the Python corpus-target in lockstep.

fn class_recall(prefix: &str) -> (usize, usize) {
    let rows: Vec<&MissCase> = MISS_TABLE
        .iter()
        .filter(|c| c.name.starts_with(prefix))
        .collect();
    let hit = rows.iter().filter(|c| surfaces(c.line, c.value)).count();
    (hit, rows.len())
}

#[test]
fn hex_key_class_meets_floor() {
    let (hit, total) = class_recall("hex");
    assert!(total >= 4, "hex-key table rows missing");
    let recall = hit as f64 / total as f64;
    assert!(
        recall >= 0.85,
        "hex-key class recall {recall:.3} ({hit}/{total}) below 0.85 target: \
         keyword-anchored bare-hex keys never become candidates (generation gap)"
    );
}

#[test]
fn base64_class_meets_floor() {
    let (hit, total) = class_recall("base64");
    assert!(total >= 3, "base64 table rows missing");
    let recall = hit as f64 / total as f64;
    assert!(
        recall >= 0.80,
        "base64 class recall {recall:.3} ({hit}/{total}) below 0.80 target: \
         raw base64 secrets with no vendor prefix never become candidates"
    );
}

#[test]
fn jwt_class_meets_floor() {
    let (hit, total) = class_recall("jwt");
    assert!(total >= 3, "jwt table rows missing");
    let recall = hit as f64 / total as f64;
    assert!(
        recall >= 0.90,
        "jwt class recall {recall:.3} ({hit}/{total}) below 0.90 target: \
         JWTs whose header does not start with `alg` (eyJhbGci) are missed. \
         the prefix anchor must broaden to the structural eyJ-header triple"
    );
}
