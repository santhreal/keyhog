//! KH-GAP-003: When `KEYHOG_REQUIRE_GPU=1`, GPU gates must panic/fail
//! — never return early with an implicit skip.

use keyhog_scanner::gpu::gpu_available;

fn gpu_required_gate() {
    let require = std::env::var("KEYHOG_REQUIRE_GPU").ok();
    let strict = matches!(require.as_deref(), Some("1") | Some("true") | Some("yes"));
    if !strict {
        return;
    }

    if !gpu_available() {
        panic!(
            "Fix: KEYHOG_REQUIRE_GPU=1 but no compatible GPU adapter — \
             fail loudly with probe detail instead of skipping GPU gates"
        );
    }
}

#[test]
fn gpu_require_env_fails_not_skips() {
    unsafe { std::env::set_var("KEYHOG_REQUIRE_GPU", "1") };
    gpu_required_gate();
    unsafe { std::env::remove_var("KEYHOG_REQUIRE_GPU") };
}
