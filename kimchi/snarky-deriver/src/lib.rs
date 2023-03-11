//! **This crate is not meant to be imported directly by users**.
//! You should import [kimchi](https://crates.io/crates/kimchi) instead.
//!
//! snarky-deriver adds a number of derives to make snarky easier to use.
//! Refer to the [snarky](https://o1-labs.github.io/proof-systems/rustdoc/kimchi/snarky/index.html) documentation.

extern crate proc_macro;
use std::collections::HashSet;

use convert_case::{Case, Casing};
use itertools::Itertools;
use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use quote::{format_ident, quote};
use syn::{
    punctuated::Punctuated, Fields, FnArg, GenericParam, PredicateType, ReturnType, TraitBound,
    TraitBoundModifier, Type, TypeParamBound, TypePath, WherePredicate,
};

const TYPES_TO_AVOID: [&str; 2] = ["KimchiCurve", "PrimeField"];

/// The [SnarkyType] derive macro.
/// It generates implementations of [`kimchi::snarky::SnarkyType`].
///
/// For example:
///
/// ```ignore
/// #[derive(kimchi::SnarkyType)]
/// struct MyType {
///   // ...
/// }
/// ```
///
#[proc_macro_derive(SnarkyType)]
pub fn derive_snarky_type(item: TokenStream) -> TokenStream {
    // parse struct
    let item_struct: syn::ItemStruct =
        syn::parse(item).expect("only structs are supported with Struct");
    let name = &item_struct.ident;
    let generics = &item_struct.generics.params;
    let fields = &item_struct.fields;

    // enforce that we have a type parameter `F: PrimeField`
    let has_f_primefield = |generic: &WherePredicate| {
        if let WherePredicate::Type(t) = generic {
            t.bounds.iter().any(|bound| {
                if let TypeParamBound::Trait(trait_bound) = bound {
                    trait_bound.path.segments.last().unwrap().ident == "PrimeField"
                } else {
                    false
                }
            })
        } else {
            false
        }
    };
    let where_clause = item_struct
        .generics
        .where_clause
        .as_ref()
        .expect("SnarkyType requires the type to have a type parameter `F: PrimeField");
    if !where_clause.predicates.iter().any(has_f_primefield) {
        panic!("SnarkyType requires the type to have a type parameter `F: PrimeField")
    };

    // collect field names and types
    let (field_names, field_types) = match fields {
        Fields::Named(fields) => fields
            .named
            .iter()
            .map(|f| (f.ident.as_ref().unwrap(), &f.ty))
            .unzip(),
        Fields::Unnamed(_fields) => todo!(),
        Fields::Unit => (vec![], vec![]),
    };

    // this deriver is used by both external users, and the kimchi crate itself,
    // so we need to change the path to kimchi depending on the context
    let (snarky_type_path, snarky_type_path_str) =
        if std::env::var("CARGO_PKG_NAME").unwrap() == "kimchi" {
            (quote! { crate::SnarkyType<F> }, "crate::SnarkyType<F>")
        } else {
            (
                quote! { ::kimchi::SnarkyType<F> },
                "::kimchi::SnarkyType<F>",
            )
        };

    // the strategy is the following:
    // - we want to produce an implementation for the given struct
    // - with the exception that we want to enforce the SnarkyType bound on every generic type

    let generics_ident: Vec<_> = generics
        .iter()
        .filter_map(|g| match g {
            GenericParam::Type(t) => Some(&t.ident),
            _ => None,
        })
        .collect();

    let name_str = name.to_string();

    //
    // We define every block of the SnarkyType implementation individually.
    //

    let auxiliary = quote! {
        type Auxiliary = (
            #( <#field_types as #snarky_type_path>::Auxiliary ),*
        );
    };

    let out_of_circuit = quote! {
        type OutOfCircuit = (
            #( <#field_types as #snarky_type_path>::OutOfCircuit ),*
        );
    };

    let size_in_field_elements = quote! {
        const SIZE_IN_FIELD_ELEMENTS: usize = #( <#field_types as #snarky_type_path>::SIZE_IN_FIELD_ELEMENTS )+*;
    };

    let to_cvars = {
        // `let (cvars_i, aux_i) = field_i.to_cvars();`
        let mut to_cvars_calls = vec![];
        for (idx, field) in field_names.iter().enumerate() {
            let idx = syn::Index::from(idx);
            let cvar_i = format_ident!("cvars_{}", idx);
            let aux_i = format_ident!("aux_{}", idx);
            to_cvars_calls.push(quote! {
                let (#cvar_i, #aux_i) = self.#field.to_cvars();
            });
        }

        // `aux_i, ...`
        let aux = (0..field_names.len())
            .map(|idx| format_ident!("aux_{}", syn::Index::from(idx)))
            .collect_vec();

        quote! {
            fn to_cvars(&self) -> (Vec<FieldVar<F>>, Self::Auxiliary) {
                let mut cvars = Vec::with_capacity(Self::SIZE_IN_FIELD_ELEMENTS);

                #( #to_cvars_calls );*

                let aux = (
                    #( #aux ),*
                );

                (cvars, aux)
            }
        }
    };

    let from_cvars_unsafe = {
        // ```
        // let end = offset + T_i::SIZE_IN_FIELD_ELEMENTS;
        // let cvars_i = &cvars[offset..end];
        // offset = end;
        // let aux_i = aux.i;
        // ```
        let mut cvars_and_aux = vec![];
        for (idx, field_ty) in field_types.iter().enumerate() {
            let idx = syn::Index::from(idx);
            let cvar_i = format_ident!("cvars_{}", idx);
            let aux_i = format_ident!("aux_{}", idx);

            cvars_and_aux.push(quote! {
                let end = offset + <#field_ty as #snarky_type_path>::SIZE_IN_FIELD_ELEMENTS;
                let #cvar_i = &cvars[offset..end];
                let offset = end;
                let #aux_i = aux.#idx;
            });
        }

        // ` T_i::from_cvars_unsafe(cvars_i, aux_i)`
        let mut from_cvars_unsafe = Vec::with_capacity(field_types.len());
        for (idx, field_ty) in field_types.iter().enumerate() {
            let idx = syn::Index::from(idx);
            let cvar_i = format_ident!("cvars_{}", idx);
            let aux_i = format_ident!("aux_{}", idx);

            from_cvars_unsafe.push(quote! {
                <#field_ty as #snarky_type_path>::from_cvars_unsafe(#cvar_i.to_vec(), #aux_i)
            });
        }

        quote! {
            fn from_cvars_unsafe(cvars: Vec<FieldVar<F>>, aux: Self::Auxiliary) -> Self {
                // TODO: do we really want an assert if it's "unsafe" anyway?
                assert_eq!(cvars.len(), Self::SIZE_IN_FIELD_ELEMENTS);

                let mut offset = 0;
                #( #cvars_and_aux );*

                Self {
                    #( #field_names: #from_cvars_unsafe ),*
                }
            }
        }
    };

    let check = {
        quote! {
            fn check(&self, cs: &mut RunState<F>) {
                #( self.#field_names.check(cs) );*
            }
        }
    };

    // constraint_system_auxiliary
    let constraint_system_auxiliary = quote! {
        fn constraint_system_auxiliary() -> Self::Auxiliary {
            (
                #( <#field_types as #snarky_type_path>::constraint_system_auxiliary() ),*
            )
        }
    };

    // value_to_field_elements
    let value_to_field_elements = {
        // `let (fields_i, aux_i) = T_i::value_to_field_elements(&self.i);`
        let mut value_to_field_elements_calls = Vec::with_capacity(field_types.len());
        for (idx, field_ty) in field_types.iter().enumerate() {
            let idx = syn::Index::from(idx);
            let fields_name = format_ident!("fields_{}", idx);
            let aux_i = format_ident!("aux_{}", idx);

            value_to_field_elements_calls.push(quote! {
                let (#fields_name, #aux_i) = <#field_ty as #snarky_type_path>::value_to_field_elements(&value.#idx);
            });
        }

        // `[fields_i, ...].concat()`
        let fields_i = (0..field_types.len())
            .map(|idx| format_ident!("fields_{}", syn::Index::from(idx)))
            .collect_vec();

        // `aux_i, ...`
        let aux_i = (0..field_types.len())
            .map(|idx| format_ident!("aux_{}", syn::Index::from(idx)))
            .collect_vec();

        quote! {
            fn value_to_field_elements(value: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary) {
                #( #value_to_field_elements_calls );*

                let fields = [ #( #fields_i ),* ].concat();

                let aux = (
                    #( #aux_i ),*
                );

                (fields, aux)
            }
        }
    };

    // value_of_field_elements
    let value_of_field_elements = {
        // ```
        // let end = offset + T_i::SIZE_IN_FIELD_ELEMENTS;
        // let cvars_i = &cvars[offset..end];
        // offset = end;
        // let aux_i = aux.i;
        // ```
        let mut fields_and_aux = vec![];
        for (idx, field_ty) in field_types.iter().enumerate() {
            let idx = syn::Index::from(idx);
            let fields_i = format_ident!("fields_{}", idx);
            let aux_i = format_ident!("aux_{}", idx);

            fields_and_aux.push(quote! {
                let end = offset + <#field_ty as #snarky_type_path>::SIZE_IN_FIELD_ELEMENTS;
                let #fields_i = &fields[offset..end];
                let offset = end;
                let #aux_i = aux.#idx;
            });
        }

        // ` T_i::value_of_field_elements(fields_i, aux_i)`
        let mut value_of_field_elements = Vec::with_capacity(field_types.len());
        for (idx, field_ty) in field_types.iter().enumerate() {
            let idx = syn::Index::from(idx);
            let fields_i = format_ident!("fields_{}", idx);
            let aux_i = format_ident!("aux_{}", idx);

            value_of_field_elements.push(quote! {
                <#field_ty as #snarky_type_path>::value_of_field_elements(#fields_i.to_vec(), #aux_i)
            });
        }

        quote! {
            fn value_of_field_elements(fields: Vec<F>, aux: Self::Auxiliary) -> Self::OutOfCircuit {
                // TODO: do we really want an assert here?
                assert_eq!(fields.len(), Self::SIZE_IN_FIELD_ELEMENTS);

                let mut offset = 0;
                #( #fields_and_aux );*

                (
                    #( #value_of_field_elements ),*
                )
            }
        }
    };

    //
    // Implementation
    //

    let (impl_generics, ty_generics, _where_clause) = item_struct.generics.split_for_impl();

    // add SnarkyType bounds to all the field types
    let mut extended_generics = item_struct.generics.clone();
    extended_generics.make_where_clause();
    let mut extended_where_clause = extended_generics.where_clause.unwrap();

    let path: syn::Path =
        syn::parse_str(snarky_type_path_str).expect("snarky_type_path_str is not a valid?");
    let impl_snarky_type = TraitBound {
        paren_token: None,
        modifier: TraitBoundModifier::None,
        lifetimes: None,
        path,
    };

    let mut types_to_bind = HashSet::new();
    for field_type in field_types {
        match field_type {
            Type::Path(_path) => types_to_bind.insert(field_type.clone()),
            // we only support paths as types for now
            _ => todo!(),
        };
    }

    let mut bounds = Punctuated::<TypeParamBound, syn::token::Add>::new();
    bounds.push(TypeParamBound::Trait(impl_snarky_type.clone()));
    for bounded_ty in types_to_bind {
        extended_where_clause
            .predicates
            .push(WherePredicate::Type(PredicateType {
                lifetimes: None,
                bounded_ty,
                colon_token: syn::token::Colon {
                    spans: [Span::call_site()],
                },
                bounds: bounds.clone(),
            }));
    }

    // generate implementations for OCamlDesc and OCamlBinding
    let gen = quote! {
        impl #impl_generics #snarky_type_path for #name #ty_generics #extended_where_clause {
            #auxiliary

            #out_of_circuit

            #size_in_field_elements

            #to_cvars

            #from_cvars_unsafe

            #check

            #constraint_system_auxiliary

            #value_to_field_elements

            #value_of_field_elements
        }
    };
    gen.into()
}
