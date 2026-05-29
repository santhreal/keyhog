//! Macros that fan a runner `fn(Profile, &str)` across every [`Profile`],
//! emitting one `#[test]` per profile inside a per-subcommand module. Hand the
//! macro a list of `module_name => "subcommand"` pairs and it builds the full
//! `(subcommand × profile)` matrix as distinct, individually-named tests.
//!
//! Every profile is listed explicitly (no codegen loop) so the set is auditable
//! and adding a profile is a deliberate edit. The macro only NAMES the cases;
//! the truth lives in the runner each cell calls.
//!
//! [`Profile`]: crate::reliability::harness::Profile

/// Emit the 16 per-profile test modules for one subcommand, each calling
/// `$runner(Profile::X, $sub)`.
#[macro_export]
macro_rules! kh_profiles {
    ($runner:path, $sub:expr) => {
        pub mod plain {
            #[test]
            fn case() {
                $runner($crate::reliability::harness::Profile::Plain, $sub);
            }
        }
        pub mod no_color {
            #[test]
            fn case() {
                $runner($crate::reliability::harness::Profile::NoColor, $sub);
            }
        }
        pub mod clicolor_force {
            #[test]
            fn case() {
                $runner($crate::reliability::harness::Profile::ClicolorForce, $sub);
            }
        }
        pub mod dumb_term {
            #[test]
            fn case() {
                $runner($crate::reliability::harness::Profile::DumbTerm, $sub);
            }
        }
        pub mod empty_term {
            #[test]
            fn case() {
                $runner($crate::reliability::harness::Profile::EmptyTerm, $sub);
            }
        }
        pub mod tiny_cols {
            #[test]
            fn case() {
                $runner($crate::reliability::harness::Profile::TinyCols, $sub);
            }
        }
        pub mod huge_cols {
            #[test]
            fn case() {
                $runner($crate::reliability::harness::Profile::HugeCols, $sub);
            }
        }
        pub mod no_home {
            #[test]
            fn case() {
                $runner($crate::reliability::harness::Profile::NoHome, $sub);
            }
        }
        pub mod empty_home {
            #[test]
            fn case() {
                $runner($crate::reliability::harness::Profile::EmptyHome, $sub);
            }
        }
        pub mod c_locale {
            #[test]
            fn case() {
                $runner($crate::reliability::harness::Profile::CLocale, $sub);
            }
        }
        pub mod utf8_locale {
            #[test]
            fn case() {
                $runner($crate::reliability::harness::Profile::Utf8Locale, $sub);
            }
        }
        pub mod bad_tmpdir {
            #[test]
            fn case() {
                $runner($crate::reliability::harness::Profile::BadTmpdir, $sub);
            }
        }
        pub mod read_only_cwd {
            #[test]
            fn case() {
                $runner($crate::reliability::harness::Profile::ReadOnlyCwd, $sub);
            }
        }
        pub mod bogus_backend {
            #[test]
            fn case() {
                $runner($crate::reliability::harness::Profile::BogusBackend, $sub);
            }
        }
        pub mod one_thread {
            #[test]
            fn case() {
                $runner($crate::reliability::harness::Profile::OneThread, $sub);
            }
        }
        pub mod many_threads {
            #[test]
            fn case() {
                $runner($crate::reliability::harness::Profile::ManyThreads, $sub);
            }
        }
    };
}

/// Build a full `(subcommand × profile)` matrix: one module per subcommand,
/// each containing the 16 per-profile tests from [`kh_profiles!`].
#[macro_export]
macro_rules! kh_matrix {
    ($runner:path, $( $name:ident => $sub:expr ),+ $(,)?) => {
        $(
            pub mod $name {
                $crate::kh_profiles!($runner, $sub);
            }
        )+
    };
}
