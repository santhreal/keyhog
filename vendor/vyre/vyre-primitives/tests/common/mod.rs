#![allow(unused_imports, unused_macros)]

pub(crate) use vyre_primitives::wire::pack_u32_slice as u32_bytes;

macro_rules! adversarial_unary_vec_cases {
    ($($name:ident: $input:expr => $expected:expr, $message:expr;)+) => {
        $(
            #[test]
            fn $name() {
                let input = $input;
                let expected = $expected;
                let actual = cpu_ref(&input);
                assert_eq!(actual, expected, "{}", $message);
            }
        )+
    };
}

macro_rules! adversarial_binary_vec_cases {
    ($($name:ident: $lhs:expr, $rhs:expr => $expected:expr, $message:expr;)+) => {
        $(
            #[test]
            fn $name() {
                let lhs = $lhs;
                let rhs = $rhs;
                let expected = $expected;
                let actual = cpu_ref(&lhs, &rhs);
                assert_eq!(actual, expected, "{}", $message);
            }
        )+
    };
}

macro_rules! adversarial_binary_vec_usize_cases {
    ($($name:ident: $lhs:expr, $rhs:expr, $len:expr => $expected:expr, $message:expr;)+) => {
        $(
            #[test]
            fn $name() {
                let lhs = $lhs;
                let rhs = $rhs;
                let len = $len;
                let expected = $expected;
                let actual = cpu_ref(&lhs, &rhs, len);
                assert_eq!(actual, expected, "{}", $message);
            }
        )+
    };
}

macro_rules! adversarial_vec_u32_cases {
    ($($name:ident: $input:expr, $param:expr => $expected:expr, $message:expr;)+) => {
        $(
            #[test]
            fn $name() {
                let input = $input;
                let param = $param;
                let expected = $expected;
                let actual = cpu_ref(&input, param);
                assert_eq!(actual, expected, "{}", $message);
            }
        )+
    };
}
