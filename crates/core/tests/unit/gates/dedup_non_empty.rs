//! Gate `dedup`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn dedup_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/dedup.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "dedup: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "dedup: todo!/unimplemented! forbidden in non-test source"
    );
    assert!(
        src.contains("fn effective_credential_hash(")
            && src.contains("credential_hash.is_zero()")
            && src.contains("effective_credential_hash(m.credential.as_ref(), m.credential_hash)")
            && src.contains(
                "effective_credential_hash(matched.credential.as_ref(), matched.credential_hash)"
            ),
        "dedup must reuse RawMatch::credential_hash, with only the zero-hash compatibility repair at the input boundary"
    );
    assert!(
        !prod.contains("sha256_hash(m.credential.as_ref())")
            && !prod.contains("sha256_hash(matched.credential.as_ref())"),
        "dedup must not unconditionally recompute SHA-256 in the per-match hot path"
    );
    assert!(
        src.contains("IndexMap::with_capacity(match_count)")
            && src.contains("Vec::with_capacity(match_count)")
            && src.contains("IndexMap::with_capacity(deduped.len())"),
        "dedup grouping tables must be pre-sized from the known input length"
    );
    assert!(
        !src.contains("IndexMap<DedupKey, DedupedMatch> = IndexMap::new()")
            && !src.contains(
                "seen_locations: Vec<std::collections::HashSet<LocIdentity>> = Vec::new()"
            )
            && !src.contains("IndexMap<GroupKey, Vec<DedupedMatch>> = IndexMap::new()"),
        "dedup hot grouping tables must not regress to zero-capacity allocation"
    );
    assert!(
        src.contains("struct FileScopeIdentity")
            && src
                .contains("type DedupKey = (Arc<str>, SensitiveString, Option<FileScopeIdentity>)")
            && !src.contains("fn file_scope_identity(location: &MatchLocation) -> Arc<str>")
            && !src.contains("let mut identity = String::new();"),
        "file-scope dedup identity must reuse existing Arc fields instead of formatting a new Arc<str> per match"
    );
    assert!(
        src.contains("struct LocationIdentityRef<'a>")
            && src.contains("impl Equivalent<LocationIdentity> for LocationIdentityRef<'_>")
            && src.contains("struct DedupKeyRef<'a>")
            && src.contains("impl Equivalent<(Arc<str>, SensitiveString, Option<FileScopeIdentity>)> for DedupKeyRef<'_>")
            && src.contains("struct CrossDetectorGroupKeyRef<'a>")
            && src.contains("impl Equivalent<(CredentialHash, Option<Arc<str>>)> for CrossDetectorGroupKeyRef<'_>")
            && src.contains("fn insert_new_location_identity(")
            && src.contains("seen.contains(&identity)")
            && src.contains("seen.insert(location_identity(location))"),
        "dedup location membership must probe with borrowed fields before cloning Arc identity fields on misses"
    );
    assert!(
        src.contains("pub credential_hash: CredentialHash")
            && src.contains("type GroupKey = (CredentialHash, Option<Arc<str>>)")
            && !src.contains("pub credential_hash: [u8; 32]")
            && !src.contains("type GroupKey = ([u8; 32]"),
        "dedup: credential hashes must stay typed through report grouping and cross-detector grouping"
    );
}
