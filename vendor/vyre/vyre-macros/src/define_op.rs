//! `define_op!` function-like macro — single-call op registration.
//!
//! Expands to: op type struct, associated `program()`, `LAWS` slice, and
//! an `inventory::submit!` registration that vyre's `DialectRegistry`
//! discovers at startup.
//!
//! Example:
//!
//! ```ignore
//! vyre_macros::define_op! {
//!     id = "primitive.bitwise.xor",
//!     dialect = "primitive.bitwise",
//!     category = A,
//!     inputs = ["u32", "u32"],
//!     outputs = ["u32"],
//!     laws = [Commutative, Associative, Identity { element: 0 }],
//!     program = |a, b| ::vyre::ir::Expr::BinOp {
//!         op: ::vyre::ir::BinOp::Xor,
//!         left: Box::new(a),
//!         right: Box::new(b),
//!     },
//! }
//! ```
//!
//! The macro body lives in this module; the public entry is
//! `crate::define_op` re-exported from lib.rs.

use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{parse_macro_input, Expr, ExprArray, LitStr, Token};

struct DefineOpArgs {
    id: LitStr,
    dialect: LitStr,
    category: syn::Ident,
    inputs: Vec<LitStr>,
    outputs: Vec<LitStr>,
    laws: Vec<Expr>,
    program: Expr,
}

impl Parse for DefineOpArgs {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut id: Option<LitStr> = None;
        let mut dialect: Option<LitStr> = None;
        let mut category: Option<syn::Ident> = None;
        let mut inputs: Vec<LitStr> = Vec::new();
        let mut outputs: Vec<LitStr> = Vec::new();
        let mut laws: Vec<Expr> = Vec::new();
        let mut program: Option<Expr> = None;

        while !input.is_empty() {
            let key: syn::Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            match key.to_string().as_str() {
                "id" => id = Some(input.parse()?),
                "dialect" => dialect = Some(input.parse()?),
                "category" => category = Some(input.parse()?),
                "inputs" => inputs = parse_str_array(input)?,
                "outputs" => outputs = parse_str_array(input)?,
                "laws" => laws = parse_expr_array(input)?,
                "program" => program = Some(input.parse()?),
                other => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!("unknown define_op! argument `{other}`"),
                    ));
                }
            }
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(Self {
            id: id.ok_or_else(|| input.error("missing `id = \"...\"`"))?,
            dialect: dialect.ok_or_else(|| input.error("missing `dialect = \"...\"`"))?,
            category: category.ok_or_else(|| input.error("missing `category = A|B|C`"))?,
            inputs,
            outputs,
            laws,
            program: program.ok_or_else(|| input.error("missing `program = |..| ..`"))?,
        })
    }
}

fn parse_str_array(input: ParseStream<'_>) -> syn::Result<Vec<LitStr>> {
    let array: ExprArray = input.parse()?;
    array
        .elems
        .into_iter()
        .map(|expr| match expr {
            Expr::Lit(lit) => match lit.lit {
                syn::Lit::Str(s) => Ok(s),
                other => Err(syn::Error::new_spanned(other, "expected string literal")),
            },
            other => Err(syn::Error::new_spanned(other, "expected string literal")),
        })
        .collect()
}

fn parse_expr_array(input: ParseStream<'_>) -> syn::Result<Vec<Expr>> {
    let array: ExprArray = input.parse()?;
    Ok(array.elems.into_iter().collect())
}

pub(crate) fn define_op_impl(item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(item as DefineOpArgs);
    let id = args.id;
    let dialect = args.dialect;
    let category = args.category;
    let inputs = &args.inputs;
    let outputs = &args.outputs;
    let laws = &args.laws;
    let program = args.program;

    quote! {
        ::inventory::submit! {
            ::vyre::dialect::OpDefRegistration::new(|| ::vyre::dialect::OpDef {
                id: #id,
                dialect: #dialect,
                category: ::vyre::dialect::Category::#category,
                signature: ::vyre::dialect::Signature {
                    inputs: &[
                        #( ::vyre::dialect::TypedParam { name: "", ty: #inputs } ),*
                    ],
                    outputs: &[
                        #( ::vyre::dialect::TypedParam { name: "", ty: #outputs } ),*
                    ],
                    attrs: &[],
                    bytes_extraction: false,
                },
                lowerings: ::vyre::dialect::LoweringTable::empty(),
                laws: &[ #( ::vyre::ops::AlgebraicLaw::#laws ),* ],
                compose: {
                    fn __vyre_compose_program() -> ::vyre::ir::Program {
                        #program
                    }
                    Some(__vyre_compose_program)
                },
            })
        }
    }
    .into()
}
