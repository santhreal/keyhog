//! Canonicalization-stability property sweep for AWS SigV4 (6318 slice 4). The
//! `regression_sigv4_known_answer` suite pins byte-for-byte signatures for fixed
//! requests; this sweep locks the INVARIANT those known answers depend on: the
//! signature is independent of the ORDER and the CASE in which the client hands
//! over headers and query parameters. SigV4 canonicalization sorts headers (via a
//! `BTreeMap`), lowercases their names, collapses value whitespace, and sorts the
//! encoded query pairs, so permuting or re-casing the inputs must produce a
//! byte-identical `Authorization` and `SignedHeaders`. If it did not, a signed
//! request would be non-reproducible and AWS would reject the verifier's probe at
//! random. Uses the SSRF sweep's hand-rolled LCG (no `proptest` dev-dep here);
//! any failing case is reproducible from its seed.

use crate::common::lcg;
use keyhog_verifier::sigv4::sign_request_authorization;

// Header names that are DISTINCT once lowercased and none of which collide with
// the auto-added `host` / `x-amz-date` (a collision would merge values in input
// order, which is legitimately order-dependent and outside this invariant).
const HEADER_NAMES: &[&str] = &[
    "content-type",
    "x-amz-target",
    "accept",
    "x-custom-a",
    "x-custom-b",
    "x-foo-bar",
];
const VALUE_CHARS: &[u8] = b"abcXYZ019 -._";

// Fixed request context, only header/query order+case varies between the two
// signings, so any signature difference isolates a canonicalization-order bug.
const ACCESS_KEY: &str = "AKIDEXAMPLE";
const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const REGION: &str = "us-east-1";
const SERVICE: &str = "s3";
const METHOD: &str = "GET";
const URI: &str = "/";
const HOST: &str = "example.amazonaws.com";
// SHA-256 of the empty payload.
const PAYLOAD_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const UNIX_SECS: u64 = 1_440_938_160;

fn build_value(state: &mut u32) -> String {
    let n = (lcg(state) as usize) % 12;
    (0..n)
        .map(|_| VALUE_CHARS[(lcg(state) as usize) % VALUE_CHARS.len()] as char)
        .collect()
}

/// Randomly upper/lower-case each ASCII-alphabetic char. Canonicalization
/// lowercases header names, so this must not change the signature.
fn random_case(name: &str, state: &mut u32) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() && lcg(state) & 1 == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect()
}

fn shuffle<T>(v: &mut [T], state: &mut u32) {
    for i in (1..v.len()).rev() {
        let j = (lcg(state) as usize) % (i + 1);
        v.swap(i, j);
    }
}

fn sign(headers: &[(String, String)], query: &[(String, String)]) -> (String, String) {
    let hdr_refs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let (authorization, _amz_date, signed_headers) = sign_request_authorization(
        ACCESS_KEY,
        SECRET_KEY,
        None,
        REGION,
        SERVICE,
        METHOD,
        URI,
        query,
        HOST,
        PAYLOAD_HASH,
        UNIX_SECS,
        &hdr_refs,
    )
    .expect("valid fixed credentials always sign");
    (authorization, signed_headers)
}

const SAMPLES: usize = 20_000;

#[test]
fn sigv4_signature_is_invariant_under_header_and_query_reorder_and_case() {
    let mut state = 0x516E_4D42;
    for _ in 0..SAMPLES {
        // A distinct-name header subset (prefix of the pool → no duplicate names).
        let count = (lcg(&mut state) as usize) % (HEADER_NAMES.len() + 1);
        let headers: Vec<(String, String)> = HEADER_NAMES[..count]
            .iter()
            .map(|n| ((*n).to_string(), build_value(&mut state)))
            .collect();
        // Query pairs (duplicate keys allowed; the full (k,v) pairs are sorted).
        let qcount = (lcg(&mut state) as usize) % 5;
        let query: Vec<(String, String)> = (0..qcount)
            .map(|_| (build_value(&mut state), build_value(&mut state)))
            .collect();

        let (auth_a, signed_a) = sign(&headers, &query);

        // Re-case names, then permute both headers and query.
        let mut permuted: Vec<(String, String)> = headers
            .iter()
            .map(|(n, v)| (random_case(n, &mut state), v.clone()))
            .collect();
        shuffle(&mut permuted, &mut state);
        let mut query_b = query.clone();
        shuffle(&mut query_b, &mut state);

        let (auth_b, signed_b) = sign(&permuted, &query_b);

        assert_eq!(
            auth_a, auth_b,
            "SigV4 Authorization changed under header/query reorder+recase. \
             canonicalization is not order-stable. headers={headers:?} query={query:?}",
        );
        assert_eq!(
            signed_a, signed_b,
            "SignedHeaders list changed under reorder+recase: {signed_a:?} != {signed_b:?}",
        );
    }
}
