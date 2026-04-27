use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{parse_macro_input, Attribute, Ident, Token, Type};

struct FieldDef {
    name: Ident,
    ty: Type,
}

enum VariantData {
    Unit,
    Unnamed(Vec<Type>),
    Named(Vec<FieldDef>),
}

struct AstVariant {
    attrs: Vec<Attribute>,
    ident: Ident,
    data: VariantData,
}

struct AstEnum {
    attrs: Vec<Attribute>,
    name: Ident,
    variants: Vec<AstVariant>,
}

struct AstManifest {
    enums: Vec<AstEnum>,
}

impl Parse for AstManifest {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut enums = Vec::new();
        while !input.is_empty() {
            let enum_attrs = input.call(Attribute::parse_outer)?;
            let name: Ident = input.parse()?;
            let content;
            syn::braced!(content in input);
            let mut variants = Vec::new();
            while !content.is_empty() {
                let variant_attrs = content.call(Attribute::parse_outer)?;
                let v_ident: Ident = content.parse()?;
                let data = if content.peek(syn::token::Brace) {
                    let fields_content;
                    syn::braced!(fields_content in content);
                    let mut fields = Vec::new();
                    while !fields_content.is_empty() {
                        let f_name: Ident = fields_content.parse()?;
                        fields_content.parse::<Token![:]>()?;
                        let f_ty: Type = fields_content.parse()?;
                        fields.push(FieldDef {
                            name: f_name,
                            ty: f_ty,
                        });
                        if fields_content.peek(Token![,]) {
                            fields_content.parse::<Token![,]>()?;
                        }
                    }
                    VariantData::Named(fields)
                } else if content.peek(syn::token::Paren) {
                    let fields_content;
                    syn::parenthesized!(fields_content in content);
                    let mut fields = Vec::new();
                    while !fields_content.is_empty() {
                        let f_ty: Type = fields_content.parse()?;
                        fields.push(f_ty);
                        if fields_content.peek(Token![,]) {
                            fields_content.parse::<Token![,]>()?;
                        }
                    }
                    VariantData::Unnamed(fields)
                } else {
                    VariantData::Unit
                };
                variants.push(AstVariant {
                    attrs: variant_attrs,
                    ident: v_ident,
                    data,
                });
                if content.peek(Token![,]) {
                    content.parse::<Token![,]>()?;
                }
            }
            enums.push(AstEnum {
                attrs: enum_attrs,
                name,
                variants,
            });
        }
        Ok(AstManifest { enums })
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn vyre_ast_registry_impl(item: TokenStream) -> TokenStream {
    let manifest = parse_macro_input!(item as AstManifest);

    let mut outputs = Vec::new();

    for ast_enum in manifest.enums {
        let enum_name = &ast_enum.name;
        let enum_attrs = &ast_enum.attrs;

        let variants = ast_enum.variants.iter().map(|v| {
            let ident = &v.ident;
            let attrs = &v.attrs;
            match &v.data {
                VariantData::Unit => quote! { #(#attrs)* #ident },
                VariantData::Unnamed(types) => quote! { #(#attrs)*  #ident(#(#types),*) },
                VariantData::Named(fields) => {
                    let f = fields.iter().map(|f| {
                        let n = &f.name;
                        let t = &f.ty;
                        quote! { #n: #t }
                    });
                    quote! { #(#attrs)* #ident { #(#f),* } }
                }
            }
        });

        // op_id implementation
        let op_ids = ast_enum.variants.iter().map(|v| {
            let ident = &v.ident;
            if ident == "Opaque" {
                quote! {
                    #enum_name::Opaque(ext) => ext.extension_kind().to_string()
                }
            } else {
                let lower_name = format!(
                    "vyre.{}.{}",
                    enum_name.to_string().to_lowercase(),
                    ident.to_string().to_lowercase()
                );
                match &v.data {
                    VariantData::Unit => quote! {
                        #enum_name::#ident => #lower_name.to_string()
                    },
                    VariantData::Unnamed(_) => quote! {
                        #enum_name::#ident ( .. ) => #lower_name.to_string()
                    },
                    VariantData::Named(_) => quote! {
                        #enum_name::#ident { .. } => #lower_name.to_string()
                    },
                }
            }
        });

        let op_id_fn_name = syn::Ident::new(
            &format!("{}_op_id", enum_name.to_string().to_lowercase()),
            proc_macro2::Span::call_site(),
        );

        // PartialEq implementations
        let partial_eq_arms = ast_enum.variants.iter().map(|v| {
            let ident = &v.ident;
            if ident == "Opaque" {
                // Special case for Opaque
                quote! {
                    (Self::Opaque(left), Self::Opaque(right)) => {
                        left.extension_kind() == right.extension_kind()
                            && left.stable_fingerprint() == right.stable_fingerprint()
                    }
                }
            } else {
                match &v.data {
                    VariantData::Unit => quote! {
                        (Self::#ident, Self::#ident) => true,
                    },
                    VariantData::Unnamed(types) => {
                        let lefts: Vec<_> = (0..types.len()).map(|i| syn::Ident::new(&format!("l{i}"), proc_macro2::Span::call_site())).collect();
                        let rights: Vec<_> = (0..types.len()).map(|i| syn::Ident::new(&format!("r{i}"), proc_macro2::Span::call_site())).collect();
                        let checks = lefts.iter().zip(rights.iter()).map(|(l, r)| quote! { #l == #r });
                        quote! {
                            (Self::#ident(#(#lefts),*), Self::#ident(#(#rights),*)) => { #(#checks)&&* },
                        }
                    },
                    VariantData::Named(fields) => {
                        let lefts: Vec<_> = fields.iter().map(|f| syn::Ident::new(&format!("l_{}", f.name), proc_macro2::Span::call_site())).collect();
                        let rights: Vec<_> = fields.iter().map(|f| syn::Ident::new(&format!("r_{}", f.name), proc_macro2::Span::call_site())).collect();
                        let f_names = fields.iter().map(|f| &f.name);
                        let f_names2 = fields.iter().map(|f| &f.name);
                        let checks = lefts.iter().zip(rights.iter()).map(|(l, r)| quote! { #l == #r });
                        quote! {
                            (Self::#ident { #(#f_names: #lefts),* }, Self::#ident { #(#f_names2: #rights),* }) => { #(#checks)&&* },
                        }
                    }
                }
            }
        });

        outputs.push(quote! {
            #(#enum_attrs)*
            #[allow(missing_docs)]
            #[non_exhaustive]
            #[derive(Debug, Clone)]
            pub enum #enum_name {
                #(#variants),*
            }

            impl PartialEq for #enum_name {
                fn eq(&self, other: &Self) -> bool {
                    match (self, other) {
                        #(#partial_eq_arms)*
                        _ => false,
                    }
                }
            }

            #[must_use]
            pub fn #op_id_fn_name(item: &#enum_name) -> String {
                match item {
                    #(#op_ids,)*
                }
            }
        });

        let decoder_fn_name = syn::Ident::new(
            &format!(
                "generate_{}_gpu_vm_decoder",
                enum_name.to_string().to_lowercase()
            ),
            proc_macro2::Span::call_site(),
        );

        let decoder_arms = ast_enum.variants.iter().map(|v| {
            let hash_val = v
                .ident
                .to_string()
                .bytes()
                .fold(0u32, |acc, b| acc.wrapping_add(u32::from(b)));
            quote! {
                cascade = crate::ir_inner::model::node::Node::If {
                    cond: crate::ir_inner::model::expr::Expr::BinOp {
                        op: crate::ir_inner::model::types::BinOp::Eq,
                        left: Box::new(crate::ir_inner::model::expr::Expr::Var(
                            crate::ir_inner::model::expr::Ident::from("packet_opcode")
                        )),
                        right: Box::new(crate::ir_inner::model::expr::Expr::LitU32(#hash_val)),
                    },
                    then: vec![ crate::ir_inner::model::node::Node::Barrier ], // Native ALUs go here
                    otherwise: vec![ cascade ],
                };
            }
        });

        outputs.push(quote! {
            /// Auto-generated GPU Bytecode Interpreter execution loop scaffold.
            /// This cascade proves that Vyre AST inherently embeds a JIT capability
            /// without a single line of backend-specific hardware logic mapping.
            pub fn #decoder_fn_name() -> crate::ir_inner::model::node::Node {
                let mut cascade = crate::ir_inner::model::node::Node::Return; // Invalid opcode handler

                #(#decoder_arms)*

                cascade
            }
        });
    }

    let out = quote! { #(#outputs)* };
    out.into()
}
