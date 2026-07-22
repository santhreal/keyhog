#![cfg(feature = "web")]

use keyhog_sources::testing::{SourceTestApi, TestApi};
use std::net::IpAddr;

macro_rules! ssrf_url_case {
    ($name:ident, $url:expr, $expected_private:expr) => {
        #[test]
        fn $name() {
            assert_eq!(
                TestApi.is_disallowed_web_host($url),
                $expected_private,
                "URL: {:?}",
                $url
            );
        }
    };
}

macro_rules! ssrf_url_cases {
    ($( $name:ident: $url:expr => $expected:expr; )*) => {
        $(ssrf_url_case!($name, $url, $expected);)*
    };
}

ssrf_url_cases! {
    public_0: "http://example.com/" => false;
    public_1: "https://github.com/santhreal/keyhog" => false;
    public_2: "http://1.1.1.1/" => false;
    public_3: "https://1.1.1.1:443/" => false;
    private_0: "http://127.0.0.1/" => true;
    private_1: "http://10.0.0.1/" => true;
    private_2: "http://172.16.0.1/" => true;
    private_3: "http://192.168.1.1/" => true;
    private_4: "http://169.254.1.1/" => true;
    private_5: "http://100.64.0.1/" => true;
    private_6: "http://0.0.0.0/" => true;
    private_7: "http://255.255.255.255/" => true;
    private_8: "http://[::1]/" => true;
    private_9: "http://[fd00::1]/" => true;
    private_10: "http://[fe80::1]/" => true;
    private_11: "http://localhost/" => true;
    private_12: "http://foo.local/" => true;
    private_13: "http://foo.internal/" => true;
    private_14: "http://foo.localdomain/" => true;
    private_15: "http://2130706433/" => true;
    private_16: "http://0x7f000001/" => true;
    private_17: "http://017700000001/" => true;
    private_18: "http://127.1/" => true;
    private_19: "http://0x7f.1/" => true;
    private_20: "file:///etc/passwd" => true;
    private_21: "ftp://example.com/" => true;
    private_22: "not-a-url" => true;
}

macro_rules! ssrf_ip_case {
    ($name:ident, $ip:expr, $expected:expr) => {
        #[test]
        fn $name() {
            let ip: IpAddr = $ip.parse().expect("valid IP");
            assert_eq!(TestApi.is_disallowed_ip(ip), $expected);
        }
    };
}

macro_rules! ssrf_ip_cases {
    ($( $name:ident: $ip:expr => $expected:expr; )*) => {
        $(ssrf_ip_case!($name, $ip, $expected);)*
    };
}

ssrf_ip_cases! {
    ip_0: "127.0.0.1" => true;
    ip_1: "10.0.0.1" => true;
    ip_2: "172.16.0.1" => true;
    ip_3: "192.168.0.1" => true;
    ip_4: "1.1.1.1" => false;
    ip_5: "8.8.8.8" => false;
    ip_6: "::1" => true;
    ip_7: "fd00::1" => true;
    ip_8: "2001:4860:4860::8888" => false;
}
