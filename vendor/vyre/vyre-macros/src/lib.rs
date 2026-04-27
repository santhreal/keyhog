#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Procedural macros for the [`vyre`](https://docs.rs/vyre) GPU compute IR
//! compiler.
//!
//! This crate is compile-time only. Downstream users import from
//! `vyre::optimizer::vyre_pass` rather than depending on this crate directly.
//!
//! The single macro is [`macro@vyre_pass`] — see that item for the full usage
//! contract, argument shape, and a worked example. A high-level narrative
//! lives in the crate [README](https://github.com/).

mod ast_registry;
mod define_op;

use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{
    parse_macro_input, Attribute, Data, DeriveInput, ExprArray, Fields, ItemStruct, LitStr, Meta,
    Token,
};

/// Function-like `define_op!` — single-site op registration via inventory.
///
/// See [`define_op`](define_op/index.html) for the full argument contract.
#[proc_macro]
pub fn define_op(item: TokenStream) -> TokenStream {
    define_op::define_op_impl(item)
}

/// Generates the declarative IR AST core (Expr and Node enums)
/// plus serialization and visitor traits.
#[proc_macro]
pub fn vyre_ast_registry(item: TokenStream) -> TokenStream {
    ast_registry::vyre_ast_registry_impl(item)
}

/// A generic marker attribute used exclusively to instruct `vyre_ast_registry!`
/// to skip generating a builder method for a specific struct field.
#[proc_macro_attribute]
pub fn skip_builder(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

struct PassArgs {
    name: LitStr,
    requires: Vec<LitStr>,
    invalidates: Vec<LitStr>,
}

impl Parse for PassArgs {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut name = None;
        let mut requires = Vec::new();
        let mut invalidates = Vec::new();

        while !input.is_empty() {
            let key: syn::Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            match key.to_string().as_str() {
                "name" => name = Some(input.parse()?),
                "requires" => requires = parse_string_array(input)?,
                "invalidates" => invalidates = parse_string_array(input)?,
                _ => {
                    return Err(syn::Error::new(
                        key.span(),
                        "unsupported vyre_pass argument. Fix: use name, requires, or invalidates.",
                    ));
                }
            }
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(Self {
            name: name.ok_or_else(|| input.error("missing pass name. Fix: add name = \"...\"."))?,
            requires,
            invalidates,
        })
    }
}

fn parse_string_array(input: ParseStream<'_>) -> syn::Result<Vec<LitStr>> {
    let array: ExprArray = input.parse()?;
    array
        .elems
        .into_iter()
        .map(|expr| match expr {
            syn::Expr::Lit(lit) => match lit.lit {
                syn::Lit::Str(value) => Ok(value),
                other => Err(syn::Error::new_spanned(
                    other,
                    "pass metadata arrays accept only string literals. Fix: use [\"analysis_name\"].",
                )),
            },
            other => Err(syn::Error::new_spanned(
                other,
                "pass metadata arrays accept only string literals. Fix: use [\"analysis_name\"].",
            )),
        })
        .collect()
}

/// Register a unit struct as a `vyre::optimizer::Pass`.
///
/// Expands to (a) a full `Pass` trait impl that forwards to your inherent
/// `analyze` / `transform` / `fingerprint` methods and (b) an
/// `inventory::submit!` that adds the pass to the global registry so
/// `vyre::optimize()` picks it up automatically.
///
/// # Arguments
///
/// | Argument       | Type        | Meaning                                                             |
/// |----------------|-------------|---------------------------------------------------------------------|
/// | `name`         | string lit  | Stable pass name used in diagnostics / ordering.                    |
/// | `requires`     | `[&str]`    | Pass names that must fire before this one.                          |
/// | `invalidates`  | `[&str]`    | Analyses invalidated when this pass rewrites the program.           |
///
/// # Required inherent methods on the annotated type
///
/// ```ignore
/// fn analyze(program: &Program) -> PassAnalysis;
/// fn transform(program: Program) -> PassResult;
/// fn fingerprint(program: &Program) -> u64;
/// ```
///
/// # Example
///
/// ```ignore
/// use vyre::optimizer::{vyre_pass, PassAnalysis, PassResult, fingerprint_program};
/// use vyre::ir::Program;
///
/// #[vyre_pass(name = "fold_zero_add", requires = [], invalidates = [])]
/// pub struct FoldZeroAdd;
///
/// impl FoldZeroAdd {
///     fn analyze(_program: &Program) -> PassAnalysis { PassAnalysis::RUN }
///     fn transform(program: Program) -> PassResult {
///         // ... real rewrite ...
///         PassResult::from_programs(&program.clone(), program)
///     }
///     fn fingerprint(program: &Program) -> u64 { fingerprint_program(program) }
/// }
/// ```
///
/// After expansion, `vyre::optimize(p)` will pick up `FoldZeroAdd` through
/// the `inventory::collect!(PassRegistration)` entry emitted by the macro.
/// No manual registration needed.
#[proc_macro_attribute]
pub fn vyre_pass(args: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as PassArgs);
    let item = parse_macro_input!(item as ItemStruct);
    let ident = &item.ident;
    let name = args.name;
    let requires = args.requires;
    let invalidates = args.invalidates;

    quote! {
        #item

        impl ::vyre::optimizer::private::Sealed for #ident {}

        impl ::vyre::optimizer::Pass for #ident {
            #[inline]
            fn metadata(&self) -> ::vyre::optimizer::PassMetadata {
                ::vyre::optimizer::PassMetadata {
                    name: #name,
                    requires: &[#(#requires),*],
                    invalidates: &[#(#invalidates),*],
                }
            }

            #[inline]
            fn analyze(&self, program: &::vyre::ir::Program) -> ::vyre::optimizer::PassAnalysis {
                Self::analyze(program)
            }

            #[inline]
            fn transform(
                &self,
                program: ::vyre::ir::Program,
            ) -> ::vyre::optimizer::PassResult {
                Self::transform(program)
            }

            #[inline]
            fn fingerprint(&self, program: &::vyre::ir::Program) -> u64 {
                Self::fingerprint(program)
            }
        }

        ::inventory::submit! {
            ::vyre::optimizer::PassRegistration {
                metadata: ::vyre::optimizer::PassMetadata {
                    name: #name,
                    requires: &[#(#requires),*],
                    invalidates: &[#(#invalidates),*],
                },
                factory: || ::std::boxed::Box::new(#ident),
            }
        }
    }
    .into()
}

/// Derive `vyre::AlgebraicLawProvider` from a `#[vyre(laws = [...])]` attribute.
///
/// Attach the derive to a unit struct (or any struct) that represents an op
/// type. List its algebraic laws in the attribute; the macro emits the trait
/// impl plus a `const LAWS: &[AlgebraicLaw]` associated item.
///
/// # Example
///
/// ```ignore
/// use vyre_macros::AlgebraicLaws;
///
/// #[derive(AlgebraicLaws)]
/// #[vyre(laws = [Commutative, Associative, "Identity { element: 0 }"])]
/// pub struct Xor;
/// ```
///
/// Expands to:
///
/// ```ignore
/// impl Xor {
///     pub const LAWS: &'static [::vyre::ops::AlgebraicLaw] = &[
///         ::vyre::ops::AlgebraicLaw::Commutative,
///         ::vyre::ops::AlgebraicLaw::Associative,
///         ::vyre::ops::AlgebraicLaw::Identity { element: 0 },
///     ];
/// }
/// impl ::vyre::ops::AlgebraicLawProvider for Xor {
///     fn laws() -> &'static [::vyre::ops::AlgebraicLaw] { Self::LAWS }
/// }
/// ```
#[proc_macro_derive(AlgebraicLaws, attributes(vyre))]
pub fn derive_algebraic_laws(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let ident = &input.ident;
    let laws = match extract_laws_attribute(&input.attrs) {
        Ok(v) => v,
        Err(e) => return e.to_compile_error().into(),
    };

    // Parse each law string as an AlgebraicLaw variant expression.
    let law_exprs = laws.iter().map(|lit| {
        let src = lit.value();
        let trimmed = src.trim();
        let path: syn::Expr = match syn::parse_str(&format!("::vyre::ops::AlgebraicLaw::{trimmed}"))
        {
            Ok(e) => e,
            Err(err) => {
                return syn::Error::new_spanned(
                    lit,
                    format!("failed to parse AlgebraicLaw variant `{trimmed}`: {err}"),
                )
                .to_compile_error();
            }
        };
        quote! { #path }
    });

    // ensure the input type is a struct/enum we can attach impls to
    match &input.data {
        Data::Struct(_) | Data::Enum(_) => {}
        Data::Union(_) => {
            return syn::Error::new_spanned(
                ident,
                "#[derive(AlgebraicLaws)] does not support unions.",
            )
            .to_compile_error()
            .into();
        }
    }

    let law_exprs_vec: Vec<_> = law_exprs.collect();

    quote! {
        impl #ident {
            /// Algebraic laws declared on this op type.
            pub const LAWS: &'static [::vyre::ops::AlgebraicLaw] = &[
                #(#law_exprs_vec),*
            ];
        }

        impl ::vyre::ops::AlgebraicLawProvider for #ident {
            fn laws() -> &'static [::vyre::ops::AlgebraicLaw] {
                Self::LAWS
            }
        }
    }
    .into()
}

fn extract_laws_attribute(attrs: &[Attribute]) -> syn::Result<Vec<LitStr>> {
    for attr in attrs {
        if !attr.path().is_ident("vyre") {
            continue;
        }
        let mut laws: Option<Vec<LitStr>> = None;
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("laws") {
                let value = meta.value()?;
                // Accept both [Commutative, Identity{element:0}] bracketed
                // identifier lists and [ "Commutative", "Identity{element:0}" ]
                // string-literal arrays.
                let lookahead = value.lookahead1();
                if lookahead.peek(syn::token::Bracket) {
                    let content;
                    syn::bracketed!(content in value);
                    let mut collected = Vec::new();
                    while !content.is_empty() {
                        if content.peek(LitStr) {
                            let lit: LitStr = content.parse()?;
                            collected.push(lit);
                        } else {
                            // parse as raw token stream up to the next comma
                            let expr: syn::Expr = content.parse()?;
                            let rendered = quote! { #expr }.to_string();
                            collected.push(LitStr::new(&rendered, expr.span()));
                        }
                        if content.peek(Token![,]) {
                            content.parse::<Token![,]>()?;
                        }
                    }
                    laws = Some(collected);
                    Ok(())
                } else {
                    Err(meta.error("expected `laws = [..]`"))
                }
            } else {
                Err(meta.error("unknown vyre() argument; expected `laws = [..]`"))
            }
        })?;
        if let Some(l) = laws {
            return Ok(l);
        }
    }
    Ok(Vec::new())
}

// Keep unused imports alive (silence the compiler's unused warnings; `Fields`
// and `Meta` are referenced through docs/future use, and removing them here
// risks churn during the open-IR migration).
#[allow(dead_code)]
fn _keep_imports_alive(_: Fields, _: Meta) {}
