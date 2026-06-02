//! Boundary test: decimal max u32 (4294967295) wraps to broadcast 255.255.255.255.
//! Code path: ssrf.rs line 189-190 `parse::<u32>()` and `Ipv4Addr::from(u32)`.
//! Contract: is_private_url must block 255.255.255.255 (broadcast) as it is explicitly
//! rejected in is_private_ip_addr_fast line 96.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_decimal_broadcast_address() {
    // 4294967295 = 0xFFFFFFFF = 255.255.255.255 (broadcast)
    // is_private_ip_addr_fast line 96: val == 0xFFFFFFFF → true
    assert!(
        is_private_url("http://4294967295/"),
        "SSRF guard must block decimal max u32 (broadcast): http://4294967295/"
    );
}

#[test]
fn ssrf_blocks_decimal_just_below_broadcast() {
    // 4294967294 = 0xFFFFFFFE = 255.255.255.254 (last before broadcast, still reserved)
    assert!(
        is_private_url("http://4294967294/"),
        "SSRF guard must block decimal max-1 u32: http://4294967294/"
    );
}

#[test]
fn ssrf_blocks_decimal_unspecified_zero() {
    // 0 = 0.0.0.0 (unspecified), blocked at line 84-85
    assert!(
        is_private_url("http://0/"),
        "SSRF guard must block decimal 0 (unspecified): http://0/"
    );
}

#[test]
fn ssrf_blocks_decimal_loopback_large_form() {
    // 2130706433 = 0x7F000001 = 127.0.0.1 (loopback)
    // Existing test exists, but boundary variant with exact value
    assert!(
        is_private_url("http://2130706433/"),
        "SSRF guard must block decimal 2130706433 (127.0.0.1): http://2130706433/"
    );
}
