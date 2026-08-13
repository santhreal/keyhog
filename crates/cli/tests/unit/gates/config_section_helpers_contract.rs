#[test]
fn config_schema_structs_reject_unknown_toml_fields() {
    let schema =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/config/schema.rs"))
            .expect("config schema source readable");

    // Count every on-disk schema struct (pub, pub(super), and pub(crate)).
    // GuardSection/LockdownSection/ConfigFile are pub(crate), the section
    // helpers exposed via ConfigFile fields are pub.
    let schema_structs = schema.matches("pub struct ").count()
        + schema.matches("pub(super) struct ").count()
        + schema.matches("pub(crate) struct ").count();
    let strict_deserializers = schema
        .matches("#[serde(default, deny_unknown_fields)]")
        .count();

    assert!(
        schema_structs > 0,
        "config schema must keep explicit deserializable structs"
    );
    assert_eq!(
        strict_deserializers, schema_structs,
        "every .keyhog.toml schema struct must deny unknown fields so typos and retired tables fail closed"
    );
    assert!(
        !schema.contains("#[serde(default)]"),
        "config schema must not accept serde(default) without deny_unknown_fields"
    );
}
