extern crate proc_macro;
use convert_case::{Case, Casing};
use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use quote::quote;
use syn::{
    punctuated::Punctuated, Fields, FnArg, GenericArgument, GenericParam, PathArguments,
    PredicateType, ReturnType, TraitBound, TraitBoundModifier, Type, TypeParamBound, TypePath,
    WherePredicate,
};

/// A macro to create OCaml bindings for a function that uses #[ocaml::func]
///
/// Note that this macro must be placed first (before `#[ocaml::func]`).
/// For example:
///
/// ```
/// #[ocaml_gen]
/// #[ocaml::func]
/// pub fn something(arg1: String) {
///   //...
/// }
/// ```
///
#[proc_macro_attribute]
pub fn ocaml_gen(_attribute: TokenStream, item: TokenStream) -> TokenStream {
    let item_fn: syn::ItemFn = syn::parse(item).unwrap();

    let rust_name = &item_fn.sig.ident;
    let inputs = &item_fn.sig.inputs;
    let output = &item_fn.sig.output;

    let ocaml_name = rust_ident_to_ocaml(rust_name.to_string());

    let inputs: Vec<_> = inputs
        .into_iter()
        .filter_map(|i| match i {
            FnArg::Typed(t) => Some(&t.ty),
            _ => None,
        })
        .collect();

    let return_value = match output {
        ReturnType::Default => quote! { "unit".to_string() },
        ReturnType::Type(_, t) => quote! {
            <#t as ::ocaml_gen::ToOcaml>::to_ocaml(env, &[])
        },
    };

    let rust_name_str = rust_name.to_string();

    let fn_name = Ident::new(&format!("{}_to_ocaml", rust_name), Span::call_site());

    let new_fn = quote! {
        pub fn #fn_name(env: &::ocaml_gen::Env, rename: Option<&'static str>) -> String {
            // function name
            let ocaml_name = rename.unwrap_or(#ocaml_name);

            // arguments
            let mut args: Vec<String> = vec![];
            #(
                args.push(
                    <#inputs as ::ocaml_gen::ToOcaml>::to_ocaml(env, &[])
                );
            );*
            let inputs = if args.len() == 0 {
                "unit".to_string()
            } else {
                args.join(" -> ")
            };

            // return value
            let return_value = #return_value;

            // return the binding
            format!(
                "external {} : {} -> {} = \"{}\"",
                ocaml_name, inputs, return_value, #rust_name_str
            )
        }
    };

    let gen = quote! {
        // don't forget to generate code that also contains the old function :)
        #item_fn
        #new_fn
    };

    gen.into()
}

//
// OcamlGen
//

/// The OcamlGen derive macro.
/// It generates implementations of ToOCaml and ToBinding on a type.
/// The type must implement [ocaml::IntoValue] and [ocaml::FromValue]
/// For example:
///
/// ```
/// use ocaml_gen::OcamlGen;
///
/// #[OcamlGen]
/// struct MyType {
///   // ...
/// }
/// ```
///
#[proc_macro_derive(OcamlGen)]
pub fn derive_ocaml_gen(item: TokenStream) -> TokenStream {
    let item_struct: syn::ItemStruct =
        syn::parse(item).expect("only structs are supported at the moment");
    let name = &item_struct.ident;
    let generics = &item_struct.generics.params;
    let fields = &item_struct.fields;

    //
    // to_ocaml
    //

    let generics_ident: Vec<_> = generics
        .iter()
        .filter_map(|g| match g {
            GenericParam::Type(t) => Some(&t.ident),
            _ => None,
        })
        .map(|ident| ident)
        .collect();

    let name_str = name.to_string();

    let to_ocaml = quote! {
        fn to_ocaml(env: &::ocaml_gen::Env, generics: &[&str]) -> String {
            // get type parameters
            let mut generics_ocaml = vec![];
            #(
                generics_ocaml.push(
                    <#generics_ident as ::ocaml_gen::ToOcaml>::to_ocaml(env, generics)
                );
            );*

            // get name
            let type_id = <Self as ::ocaml_gen::ToOcaml>::to_id();
            let name = env.get_type(type_id);

            // return the type description in OCaml
            format!("({}) {}", generics_ocaml.join(", "), name)
        }
    };

    //
    // to_id
    //

    let to_id = quote! {
        fn to_id() -> u128 {
            ::ocaml_gen::const_random!(u128)
        }
    };

    //
    // to_binding
    //

    let generics_str: Vec<String> = generics
        .iter()
        .filter_map(|g| match g {
            GenericParam::Type(t) => Some(&t.ident),
            _ => None,
        })
        .map(|ident| ident.to_string())
        .collect();

    let body = match fields {
        Fields::Named(fields) => {
            let mut punctured_generics_name: Vec<String> = vec![];
            let mut punctured_generics_type: Vec<String> = vec![];
            let mut fields_to_call = vec![];
            for field in &fields.named {
                let name = field.ident.as_ref().expect("a named field has an ident");
                punctured_generics_name.push(name.to_string());
                if let Some(ty) = is_generic(&generics_str, &field.ty) {
                    punctured_generics_type.push(format!("'{}", ty));
                } else {
                    punctured_generics_type.push("#".to_string());
                    fields_to_call.push(&field.ty);
                }
            }
            fields_to_call.reverse();

            quote! {
                let mut generics_ocaml: Vec<String> = vec![];
                let punctured_generics_name: Vec<&str> = vec![
                    #(#punctured_generics_name),*
                ];
                let punctured_generics_type: Vec<&str> = vec![
                    #(#punctured_generics_type),*
                ];

                let mut missing_types: Vec<String> = vec![];
                #(
                    missing_types.push(
                        <#fields_to_call as ::ocaml_gen::ToOcaml>::to_ocaml(env, &global_generics)
                    );
                );*

                for (name, ty) in punctured_generics_name.into_iter().zip(punctured_generics_type) {
                    if ty != "#" {
                        generics_ocaml.push(
                            format!("{}: {}", name, ty.to_string())
                        );
                    } else {
                        let ty = missing_types
                            .pop()
                            .expect("number of types to call should match number of missing types");
                        generics_ocaml.push(
                            format!("{}: {}", name, ty)
                        );
                    }
                }
                format!("{{ {} }}", generics_ocaml.join("; "))
            }
        }
        Fields::Unnamed(fields) => {
            // TODO: when there's a single element,
            // this will produce something like this:
            //
            // ```
            // type ('field) scalar_challenge = 'field
            // ```
            //
            // shouldn't we instead produce something like this?
            //
            // ```
            // type ('field) scalar_challenge =  { inner: 'field }
            // ```
            let mut punctured_generics: Vec<String> = vec![];
            let mut fields_to_call = vec![];
            for field in &fields.unnamed {
                if let Some(ident) = is_generic(&generics_str, &field.ty) {
                    punctured_generics.push(format!("'{}", ident));
                } else {
                    punctured_generics.push("#".to_string());
                    fields_to_call.push(&field.ty);
                }
            }
            fields_to_call.reverse();

            quote! {
                let mut generics_ocaml: Vec<String> = vec![];

                let punctured_generics: Vec<&str> = vec![
                    #(#punctured_generics),*
                ];

                let mut missing_types: Vec<String> = vec![];
                #(
                    missing_types.push(&<#fields_to_call>::to_ocaml(env, &global_generics));
                );*

                for ty in punctured_generics {
                    if ty != "#" {
                        generics_ocaml.push(ty.to_string());
                    } else {
                        let ident = missing_types
                            .pop()
                            .expect("number of types to call should match number of missing types");
                        generics_ocaml.push(ident);
                    }
                }

                generics_ocaml.join(" * ")
            }
        }
        _ => panic!("only named, and unnamed field supported"),
    };

    let ocaml_name = rust_ident_to_ocaml(name_str);

    let to_binding = quote! {
        fn to_binding(
            env: &mut ::ocaml_gen::Env,
            rename: Option<&'static str>,
        ) -> String {
            // register the new type
            let ty_name = rename.unwrap_or(#ocaml_name);
            let ty_id = <Self as ::ocaml_gen::ToOcaml>::to_id();
            env.new_type(ty_id, ty_name);


            let global_generics: Vec<&str> = vec![#(#generics_str),*];
            let generics_ocaml = {
                #body
            };

            let name = <Self as ::ocaml_gen::ToOcaml>::to_ocaml(env, &global_generics);

            format!("type {} = {}", name, generics_ocaml)
        }
    };

    //
    // Implementations
    //

    let (impl_generics, ty_generics, _where_clause) = item_struct.generics.split_for_impl();

    // add ToOcaml bounds to the generic types
    let mut extended_generics = item_struct.generics.clone();
    extended_generics.make_where_clause();
    let mut extended_where_clause = extended_generics.where_clause.unwrap();
    let path: syn::Path = syn::parse_str("::ocaml_gen::ToOcaml").unwrap();
    let impl_to_ocaml = TraitBound {
        paren_token: None,
        modifier: TraitBoundModifier::None,
        lifetimes: None,
        path,
    };
    for generic in generics {
        match generic {
            GenericParam::Type(t) => {
                let mut bounds = Punctuated::<TypeParamBound, syn::token::Add>::new();
                bounds.push(TypeParamBound::Trait(impl_to_ocaml.clone()));

                let path: syn::Path = syn::parse_str(&t.ident.to_string()).unwrap();

                let bounded_ty = Type::Path(TypePath { qself: None, path });

                extended_where_clause
                    .predicates
                    .push(WherePredicate::Type(PredicateType {
                        lifetimes: None,
                        bounded_ty,
                        colon_token: syn::token::Colon {
                            spans: [Span::call_site()],
                        },
                        bounds,
                    }));
            }
            _ => (),
        };
    }

    // generate implementations for ToOcaml and ToBinding
    let gen = quote! {
        impl #impl_generics ::ocaml_gen::ToOcaml for #name #ty_generics #extended_where_clause {
            #to_ocaml
            #to_id
        }

        impl #impl_generics ::ocaml_gen::ToBinding for #name #ty_generics  #extended_where_clause {
            #to_binding
        }
    };
    gen.into()
}

//
// almost same code for custom types
//

/// Derives implementations for ToOcaml and ToBinding on a custom type
/// For example:
///
/// ```
/// use ocaml_gen::OCamlCustomType;
///
/// #[OCamlCustomType]
/// struct MyCustomType {
///   // ...
/// }
/// ```
///
#[proc_macro_derive(OCamlCustomType)]
pub fn derive_ocaml_custom(item: TokenStream) -> TokenStream {
    let item_struct: syn::ItemStruct =
        syn::parse(item).expect("only structs are supported at the moment");
    let name = &item_struct.ident;

    //
    // to_ocaml
    //

    let name_str = name.to_string();

    let to_ocaml = quote! {
        fn to_ocaml(env: &::ocaml_gen::Env, _generics: &[&str]) -> String {
            let type_id = <Self as ::ocaml_gen::ToOcaml>::to_id();
            env.get_type(type_id)
        }
    };

    //
    // to_id
    //

    let to_id = quote! {
        fn to_id() -> u128 {
            ::ocaml_gen::const_random!(u128)
        }
    };

    //
    // to_binding
    //

    let ocaml_name = rust_ident_to_ocaml(name_str);

    let to_binding = quote! {
        fn to_binding(
            env: &mut ::ocaml_gen::Env,
            rename: Option<&'static str>,
        ) -> String {
            // register the new type
            let ty_name = rename.unwrap_or(#ocaml_name);
            let ty_id = <Self as ::ocaml_gen::ToOcaml>::to_id();
            env.new_type(ty_id, ty_name);
            let name = <Self as ::ocaml_gen::ToOcaml>::to_ocaml(env, &[]);
            format!("type {}", name)
        }
    };

    //
    // Implementations
    //

    let (impl_generics, ty_generics, where_clause) = item_struct.generics.split_for_impl();

    // generate implementations for ToOcaml and ToBinding
    let gen = quote! {
        impl #impl_generics ::ocaml_gen::ToOcaml for #name #ty_generics #where_clause {
            #to_ocaml
            #to_id
        }

        impl #impl_generics ::ocaml_gen::ToBinding for #name #ty_generics  #where_clause {
            #to_binding
        }
    };

    gen.into()
}

//
// helpers
//

/// OCaml identifiers are snake_case, whereas Rust identifiers are CamelCase
fn rust_ident_to_ocaml(ident: String) -> String {
    ident.to_case(Case::Snake)
}

/// return true if the type passed is a generic
fn is_generic(generics: &Vec<String>, ty: &Type) -> Option<String> {
    match ty {
        Type::Path(p) => {
            if let Some(ident) = p.path.get_ident() {
                let ident = ident.to_string();
                if generics.contains(&ident) {
                    return Some(ident);
                }
            }
        }
        _ => (),
    }
    return None;
}
