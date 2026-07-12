//! #106 recall lock: database connection-string credentials across the wire
//! formats real apps emit them in — URI authority (postgres/mysql/mongodb+srv/
//! redis/amqp), JDBC query params, ADO.NET / libpq / ODBC key-value DSNs, and
//! framework config keys. keyhog already covers these through `url-credentials`
//! (any-scheme userinfo password) and `generic-password` (the `password=`/
//! `Password=`/`Pwd=` assignment), so this is a recall-assurance lock that pins
//! every form keeps surfacing — never `!is_empty`, always the exact password
//! bytes via the on-disk scanner.
//!
//! Each password is a 14-20 char alphanumeric token (no `.`) so it clears both
//! the `url-credentials` {6,} and `generic-password` {12,} floors and is not a
//! dictionary word.

mod support;

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;
use std::sync::OnceLock;
use support::contracts::{make_chunk, scanner};

/// One shared compiled scanner for the whole file — `scanner()` recompiles all
/// detectors per call, so caching keeps the suite fast. `CompiledScanner` is
/// `Send + Sync` (the CLI holds it behind an `Arc`); the harness runs these
/// `#[test]`s serially (`--test-threads=1`) so the per-scan fragment-cache clear
/// never races.
fn shared() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(scanner)
}

/// True iff scanning `text` surfaces `password` — i.e. some finding's credential
/// CONTAINS it. Connection-string detectors (postgres/mysql/redis/…) capture the
/// WHOLE URL as the credential, so the embedded password is recoverable from
/// that finding even when a service-anchored whole-URL match outranks the
/// password-only `url-credentials` match in resolution. The recall contract is
/// only that the password value reaches a finding, not which detector owns it.
fn password_surfaces(text: &str, password: &str) -> bool {
    let s = shared();
    s.clear_fragment_cache();
    let chunk: Chunk = make_chunk(text, "filesystem", "conn.conf");
    s.scan(&chunk)
        .into_iter()
        .any(|m| m.credential.to_string().contains(password))
}

/// The detector ids whose credential contains `password`, for asserting routing.
fn detectors_for(text: &str, password: &str) -> Vec<String> {
    let s = shared();
    s.clear_fragment_cache();
    let chunk: Chunk = make_chunk(text, "filesystem", "conn.conf");
    s.scan(&chunk)
        .into_iter()
        .filter(|m| m.credential.to_string().contains(password))
        .map(|m| m.detector_id.to_string())
        .collect()
}

// ── URI authority connection strings (scheme://user:PASSWORD@host) ───────────

#[test]
fn postgres_uri_password_surfaces() {
    let pw = "Pg5ecretPass99Xy";
    assert!(password_surfaces(
        &format!("postgres://app:{pw}@db.example.com:5432/mydb"),
        pw
    ));
}

#[test]
fn postgresql_uri_password_surfaces() {
    let pw = "Adm1nPassXyz789Qw";
    assert!(password_surfaces(
        &format!("postgresql://admin:{pw}@localhost/app"),
        pw
    ));
}

#[test]
fn mysql_uri_password_surfaces() {
    let pw = "MyR00tSecret123Ab";
    assert!(password_surfaces(
        &format!("mysql://root:{pw}@10.0.0.5:3306/data"),
        pw
    ));
}

#[test]
fn mongodb_uri_password_surfaces() {
    let pw = "M0ngoSecretPw88Cd";
    assert!(password_surfaces(
        &format!("mongodb://dbuser:{pw}@cluster0.example.com:27017/test"),
        pw
    ));
}

#[test]
fn mongodb_srv_uri_password_surfaces() {
    let pw = "SrvP4ssw0rdAtlas12";
    assert!(password_surfaces(
        &format!("mongodb+srv://user:{pw}@cluster0.abcde.mongodb.net/db"),
        pw
    ));
}

#[test]
fn redis_uri_empty_user_password_surfaces() {
    let pw = "RedisAuthPw45678Ef";
    assert!(password_surfaces(
        &format!("redis://:{pw}@redis.example.com:6379/0"),
        pw
    ));
}

#[test]
fn rediss_tls_uri_password_surfaces() {
    let pw = "RedisTlsPw998877Gh";
    assert!(password_surfaces(
        &format!("rediss://default:{pw}@redis.example.com:6380"),
        pw
    ));
}

#[test]
fn amqp_uri_password_surfaces() {
    let pw = "Rabb1tMqP4sswordIj";
    assert!(password_surfaces(
        &format!("amqp://guest:{pw}@broker.example.com:5672/vhost"),
        pw
    ));
}

#[test]
fn amqps_tls_uri_password_surfaces() {
    let pw = "AmqpsSecur3Pass99Kl";
    assert!(password_surfaces(
        &format!("amqps://svc:{pw}@mq.example.com:5671"),
        pw
    ));
}

#[test]
fn sqlalchemy_driver_qualified_uri_password_surfaces() {
    let pw = "SqlAlchemyPw98765Mn";
    assert!(password_surfaces(
        &format!("postgresql+psycopg2://user:{pw}@h/db"),
        pw
    ));
}

// ── JDBC connection strings (password in a query parameter) ──────────────────

#[test]
fn jdbc_postgresql_query_password_surfaces() {
    let pw = "Jdbc5ecretPw1234Op";
    assert!(password_surfaces(
        &format!("jdbc:postgresql://db:5432/app?user=admin&password={pw}"),
        pw,
    ));
}

#[test]
fn jdbc_mysql_query_password_surfaces() {
    let pw = "JdbcMy5qlPass987Qr";
    assert!(password_surfaces(
        &format!("jdbc:mysql://h:3306/d?user=root&password={pw}"),
        pw,
    ));
}

#[test]
fn jdbc_sqlserver_semicolon_password_surfaces() {
    let pw = "JdbcMsSqlPass5678St";
    assert!(password_surfaces(
        &format!("jdbc:sqlserver://h:1433;databaseName=app;password={pw}"),
        pw,
    ));
}

// ── key-value DSNs (ADO.NET / libpq / ODBC) ──────────────────────────────────

#[test]
fn adonet_dsn_password_surfaces() {
    let pw = "Ado5ecretPwLong1Uv";
    assert!(password_surfaces(
        &format!("Server=tcp:db.example.com;Database=app;User Id=admin;Password={pw};"),
        pw,
    ));
}

#[test]
fn libpq_keyword_dsn_password_surfaces() {
    let pw = "Libpq5ecretPass1Wx";
    assert!(password_surfaces(
        &format!("host=localhost port=5432 dbname=mydb user=admin password={pw}"),
        pw,
    ));
}

#[test]
fn odbc_pwd_dsn_password_surfaces() {
    let pw = "Odbc5ecretPwLong22Yz";
    assert!(password_surfaces(
        &format!("Driver={{PostgreSQL}};Server=h;Database=d;Uid=admin;Pwd={pw};"),
        pw,
    ));
}

// ── framework / env config keys ──────────────────────────────────────────────

#[test]
fn database_url_env_assignment_password_surfaces() {
    let pw = "DbUrlEnvSecret789Ab";
    assert!(password_surfaces(
        &format!("DATABASE_URL=postgres://u:{pw}@h/db"),
        pw
    ));
}

#[test]
fn spring_datasource_password_surfaces() {
    let pw = "SpringDsPass123456Cd";
    assert!(password_surfaces(
        &format!("spring.datasource.password={pw}"),
        pw
    ));
}

#[test]
fn dotnet_appsettings_connection_string_password_surfaces() {
    let pw = "NetAppSettingsPw12Ef";
    assert!(password_surfaces(
        &format!("\"DefaultConnection\": \"Server=h;Database=d;User=sa;Password={pw};\""),
        pw,
    ));
}

#[test]
fn redis_conf_requirepass_password_surfaces() {
    let pw = "MyR3disConfigPass99Gh";
    assert!(password_surfaces(&format!("requirepass {pw}"), pw));
}

// ── routing + precision spot-checks ──────────────────────────────────────────

#[test]
fn postgres_uri_routes_through_a_credential_detector() {
    let pw = "RoutingProofPw5566Ij";
    let ids = detectors_for(&format!("postgres://u:{pw}@h:5432/db"), pw);
    assert!(
        !ids.is_empty()
            && ids.iter().any(|id| id.contains("postgres")
                || id == "url-credentials"
                || id == "generic-password"),
        "postgres URI password must route through a connection/credential detector; got {ids:?}"
    );
}

#[test]
fn requirepass_below_floor_value_does_not_surface() {
    // The new requirepass/masterauth pattern has a {6,} floor: a sub-floor token
    // (a bare directive mention) must not raise a finding for that token.
    assert!(
        !password_surfaces("# requirepass abc sets the password", "abc"),
        "a 3-char requirepass token is below the floor and must not surface"
    );
}
