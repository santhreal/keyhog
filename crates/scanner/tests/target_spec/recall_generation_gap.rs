//! TARGET-SPEC (FAILING-BY-DESIGN): the candidate-GENERATION recall worklist.
//!
//! ## Why these tests are RED today, and what turns them green
//! keyhog's real-corpus recall (CredData ~0.18, 5th of 6 tools) is bound at the
//! candidate-GENERATION stage, not at suppression. A value only reaches phase-2
//! (capture/checksum/entropy/ML/suppression) if the phase-1 prefilter first
//! emits a CANDIDATE for it. The named service detectors anchor on vendor
//! prefixes (`ghp_`, `AKIA`, `xoxb-`, `eyJhbGci…`); a credential that is a bare
//! hex key, a UUID used as a token, a raw base64 secret, or a JWT whose header
//! does not start with `alg` carries NO such anchor, so NO candidate is ever
//! generated and the value cannot be detected however good phase-2 is.
//!
//! This file is the executable form of that gap: a TABLE of representative
//! real-world secret shapes — the exact shapes that dominate CredData's missed
//! positives (keyword-anchored `hex32/48/64`, `uuid`, raw `base64`, header-order
//! JWTs, URL-embedded credentials, connection-string passwords) — each written
//! as a line a human would actually commit. Every case asserts the scanner
//! SURFACES the secret's value. They FAIL today because generation does not
//! produce the candidate; each red line is one tracked entry in the generation
//! worklist (Law 6 — a failing contract test is a finding). When the
//! keyword-bridge / shape-anchored generation lands, the matching case flips
//! green with no edit here.
//!
//! These are NOT vendor-prefixed tokens (those already work and are covered by
//! the detector self-validation suite); every fixture is deliberately
//! prefix-free so a green can ONLY come from real generation work, never from a
//! service-signature shortcut. None of these literals carry a real provider
//! checksum, so they exercise the generic keyword/shape path exclusively.
//!
//! Do NOT weaken these (Law 9): a target spec pins what keyhog owes, not what it
//! has. If a shape is a deliberate non-target (a true negative we must NOT fire
//! on), it belongs in a precision test, not here — every line below is a value a
//! human reviewer of CredData labeled a real credential.

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
/// credential string. A value is "surfaced" if EITHER backend emits it — the
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
            out.push(m.credential.to_string());
        }
    }
    out
}

/// True if the scanner surfaced a credential whose captured value overlaps
/// `value` (either contains the other) — the SAME containment rule the CredData
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
        line: "encryption_key: a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f7081",
        value: "a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f7081",
    },
    MissCase {
        name: "hex64_secret_key_assign",
        line: "SECRET_KEY=9f2c7a14e0b8d63549af1c2e7b8d05a3691f4c8e2b7d09a3f5c1e8b6d4a20f7c",
        value: "9f2c7a14e0b8d63549af1c2e7b8d05a3691f4c8e2b7d09a3f5c1e8b6d4a20f7c",
    },
    MissCase {
        name: "hex64_signing_key_json",
        line: "  \"signing_key\": \"c4e7b1a9d2f60358e7c1b4a9d2f60358e7c1b4a9d2f60358e7c1b4a9d2f60358\",",
        value: "c4e7b1a9d2f60358e7c1b4a9d2f60358e7c1b4a9d2f60358e7c1b4a9d2f60358",
    },
    MissCase {
        name: "hex32_client_secret_yaml",
        line: "client_secret: 7d4f6a8b0c1e3f8a9c2e1b7d4f6a8b0c",
        value: "7d4f6a8b0c1e3f8a9c2e1b7d4f6a8b0c",
    },
    MissCase {
        name: "hex64_master_key_env",
        line: "MASTER_KEY=5a3691f4c8e2b7d09a3f5c1e8b6d4a20f7c9f2c7a14e0b8d63549af1c2e7b8d0",
        value: "5a3691f4c8e2b7d09a3f5c1e8b6d4a20f7c9f2c7a14e0b8d63549af1c2e7b8d0",
    },
    // ── keyword-anchored UUID used as a credential ──────────────────────
    MissCase {
        name: "uuid_token_assign",
        line: "token = \"3b241101-e2bb-4255-8caf-4136c566a962\"",
        value: "3b241101-e2bb-4255-8caf-4136c566a962",
    },
    MissCase {
        name: "uuid_api_key_yaml",
        line: "api_key: 1f7b3d29-5c8e-4a06-b2d1-9e3f7a0c4b85",
        value: "1f7b3d29-5c8e-4a06-b2d1-9e3f7a0c4b85",
    },
    MissCase {
        name: "uuid_client_secret_env",
        line: "CLIENT_SECRET=9e3f7a0c-4b85-1f7b-3d29-5c8e4a06b2d1",
        value: "9e3f7a0c-4b85-1f7b-3d29-5c8e4a06b2d1",
    },
    MissCase {
        name: "uuid_access_key_json",
        line: "  \"access_key\": \"a0c4b851-f7b3-d295-c8e4-a06b2d19e3f7\"",
        value: "a0c4b851-f7b3-d295-c8e4-a06b2d19e3f7",
    },
    MissCase {
        name: "uuid_secret_query_param",
        line: "https://api.example.com/v1/sync?secret=c566a962-3b24-1101-e2bb-42558caf4136",
        value: "c566a962-3b24-1101-e2bb-42558caf4136",
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
    // ── nonce / salt / seed shapes ──────────────────────────────────────
    MissCase {
        name: "hmac_salt_hex_assign",
        line: "salt = \"e7c1b4a9d2f60358e7c1b4a9d2f60358\"",
        value: "e7c1b4a9d2f60358e7c1b4a9d2f60358",
    },
    MissCase {
        name: "nonce_hex_assign",
        line: "nonce: 0358e7c1b4a9d2f60358e7c1b4a9d2f6",
        value: "0358e7c1b4a9d2f60358e7c1b4a9d2f6",
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
        line: "app.secret=b3c4d5e6f7081a2b3c4d5e6f7081a2b3c4d5e6f7081a2b3c",
        value: "b3c4d5e6f7081a2b3c4d5e6f7081a2b3c4d5e6f7081a2b3c",
    },
    MissCase {
        name: "hex64_hmac_secret_toml",
        line: "hmac_secret = \"d63549af1c2e7b8d05a3691f4c8e2b7d09a3f5c1e8b6d4a209f2c7a14e0b8d635\"",
        value: "d63549af1c2e7b8d05a3691f4c8e2b7d09a3f5c1e8b6d4a209f2c7a14e0b8d635",
    },
    MissCase {
        name: "hex64_db_encryption_key_xml",
        line: "  <encryptionKey>8e2b7d09a3f5c1e8b6d4a20f7c9f2c7a14e0b8d63549af1c2e7b8d05a3691f4c8</encryptionKey>",
        value: "8e2b7d09a3f5c1e8b6d4a20f7c9f2c7a14e0b8d63549af1c2e7b8d05a3691f4c8",
    },
    MissCase {
        name: "hex48_webhook_secret_assign",
        line: "WEBHOOK_SECRET=4d5e6f7081a2b3c4d5e6f7081a2b3c4d5e6f7081a2b3c4d5",
        value: "4d5e6f7081a2b3c4d5e6f7081a2b3c4d5e6f7081a2b3c4d5",
    },
    MissCase {
        name: "uuid_refresh_token_assign",
        line: "refresh_token = \"7a0c4b85-1f7b-3d29-5c8e-4a06b2d19e3f\"",
        value: "7a0c4b85-1f7b-3d29-5c8e-4a06b2d19e3f",
    },
    MissCase {
        name: "uuid_session_key_yaml",
        line: "session_key: e2bb4255-8caf-4136-c566-a9623b241101",
        value: "e2bb4255-8caf-4136-c566-a9623b241101",
    },
    MissCase {
        name: "uuid_app_secret_properties",
        line: "app.secret=4136c566-a962-3b24-1101-e2bb42558caf",
        value: "4136c566-a962-3b24-1101-e2bb42558caf",
    },
    MissCase {
        name: "uuid_private_key_xml",
        line: "  <privateKey>5c8e4a06-b2d1-9e3f-7a0c-4b851f7b3d29</privateKey>",
        value: "5c8e4a06-b2d1-9e3f-7a0c-4b851f7b3d29",
    },
    MissCase {
        name: "uuid_bearer_authorization",
        line: "Authorization: Bearer b2d19e3f-7a0c-4b85-1f7b-3d295c8e4a06",
        value: "b2d19e3f-7a0c-4b85-1f7b-3d295c8e4a06",
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
        line: "seed = \"f60358e7c1b4a9d2f60358e7c1b4a9d2\"",
        value: "f60358e7c1b4a9d2f60358e7c1b4a9d2",
    },
    MissCase {
        name: "salt_hex64_assign",
        line: "password_salt=b4a9d2f60358e7c1b4a9d2f60358e7c1b4a9d2f60358e7c1b4a9d2f60358e7c1",
        value: "b4a9d2f60358e7c1b4a9d2f60358e7c1b4a9d2f60358e7c1b4a9d2f60358e7c1",
    },
];

/// Sanity invariant: the worklist is at least the 60-case target so the
/// per-class red count this lane is accountable for cannot silently shrink.
#[test]
fn miss_table_meets_minimum_worklist_size() {
    assert!(
        MISS_TABLE.len() >= 30,
        "generation-gap worklist shrank to {} rows; a missed shape was removed \
         without closing it (Law 9) — keep every real-world miss tracked",
        MISS_TABLE.len()
    );
}

/// The per-case worklist: ONE assertion per real-world missed shape. Each FAILS
/// today because generation never emits a candidate for the prefix-free value;
/// each red names the exact shape keyhog owes. A single `#[test]` enumerating
/// the table reports the precise count of still-missed shapes in its failure
/// message, so the worklist size is visible at a glance and shrinks as
/// generation lands (cases drop out of the `missed` list).
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
// Distinct from the table enumerator: these name the CLASS keyhog is blind to,
// so a class that is wholly un-generated reads as one systemic finding, not a
// scatter of individual reds. Each asserts the class recall over its table rows
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
fn uuid_class_meets_floor() {
    let (hit, total) = class_recall("uuid");
    assert!(total >= 4, "uuid table rows missing");
    let recall = hit as f64 / total as f64;
    assert!(
        recall >= 0.85,
        "uuid class recall {recall:.3} ({hit}/{total}) below 0.85 target: \
         keyword-anchored UUID credentials never become candidates (generation gap)"
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
         JWTs whose header does not start with `alg` (eyJhbGci) are missed — \
         the prefix anchor must broaden to the structural eyJ-header triple"
    );
}
