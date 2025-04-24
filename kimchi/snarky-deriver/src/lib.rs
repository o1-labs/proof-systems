//! snarky-deriver adds a number of derives to make snarky easier to use.
//! Refer to the
//! [snarky](https://o1-labs.github.io/proof-systems/rustdoc/kimchi/snarky/index.html)
//! documentation.

extern crate proc_macro;
use std::collections::HashSet;

use itertools::Itertools;
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{format_ident, quote};
use syn::{
    punctuated::Punctuated, Fields, Lit, MetaNameValue, PredicateType, TraitBound,
    TraitBoundModifier, Type, TypeParamBound, WherePredicate,
};

/// The [SnarkyType] derive macro.
/// It generates implementations of \[`kimchi::snarky::SnarkyType`\],
/// as long as your structure's fields implement that type as well.
/// It works very similarly to \[`serde`\].
///
/// For example:
///
/// ```ignore
/// #[derive(kimchi::SnarkyType)]
/// struct MyType<F> where F: PrimeField {
///   // ...
/// }
/// ```
///
/// You can specify your snarky type implementation to only apply to a single
/// field (e.g. `Fp`), or to apply to a field that has a different name than
/// `F`:
///
/// ```text
/// #[derive(kimchi::SnarkyType)]
/// #[snarky(field = "G::ScalarField")]
/// struct MyType<G> where G: KimchiCurve {
/// ```
///
/// You can skip a field in the serializer:
///
/// ```text
/// #[derive(kimchi::SnarkyType)]
/// struct MyType<F> where F: PrimeField {
///  #[snarky(skip)]
/// field_to_skip: NotASnarkyType,
/// ```
///
/// Finally, you can specify a custom check function,
/// as well as a custom auxiliary function and type:
///
/// ```text
/// #[derive(kimchi::SnarkyType)]
/// #[snarky(check_fn = "my_check_fn")]
/// #[snarky(auxiliary_fn = "my_auxiliary_fn")]
/// #[snarky(auxiliary_type = "MyAuxiliaryType")]
/// struct MyType<F> where F: PrimeField {
/// ```
///
/// By default, a tuple will be use to represent the out-of-circuit type.
/// You can specify it yourself by using the `value` helper attribute:
///
/// ```text
/// #[derive(kimchi::SnarkyType)]
/// #[snarky(value = "MyOutOfCircuitType")]
/// struct MyType<F> where F: PrimeField {
/// ```
///
/// and implement the \[`CircuitAndValue`\] trait on your \[`SnarkyType`\].
///
#[proc_macro_derive(SnarkyType, attributes(snarky))]
pub fn derive_snarky_type(item: TokenStream) -> TokenStream {
    // The strategy is the following:
    //
    // - we want to produce an implementation for the given struct
    // - with the exception that we want to enforce the SnarkyType bound on every generic type

    // parse struct
    let item_struct: syn::ItemStruct =
        syn::parse(item).expect("only structs are supported with `SnarkyType` at the moment");

    // parse macro attributes into our cfg struct
    // warning: parsing macro attributes is hairy
    #[derive(Default)]
    struct HelperAttributes {
        field: Option<String>,
        check_fn: Option<String>,
        auxiliary_fn: Option<String>,
        auxiliary_type: Option<String>,
        value: Option<String>,
    }
    let mut helper_attributes = HelperAttributes::default();

    let malformed_snarky_helper =
        "snarky helper malformed. It should look like `#[snarky(key = value)]`";
    for attr in &item_struct.attrs {
        if let Ok(syn::Meta::List(meta)) = attr.parse_meta() {
            // we only care about `#[snarky(...)]`
            if !meta.path.is_ident("snarky") {
                continue;
            }

            for meta_inner in meta.nested {
                match meta_inner {
                    syn::NestedMeta::Meta(syn::Meta::NameValue(MetaNameValue {
                        path,
                        eq_token: _,
                        lit,
                    })) => {
                        let value = match lit {
                            Lit::Str(lit) => lit.value(),
                            _ => panic!("{malformed_snarky_helper}"),
                        };
                        if path.is_ident("field") {
                            helper_attributes.field = Some(value);
                        } else if path.is_ident("check_fn") {
                            helper_attributes.check_fn = Some(value);
                            panic!("`check_fn` is not supported yet. Post an issue with this error to request it (https://github.com/o1-labs/proof-systems/issues)");
                        } else if path.is_ident("auxiliary_fn") {
                            helper_attributes.auxiliary_fn = Some(value);
                            panic!("`auxiliary_fn` is not supported yet. Post an issue with this error to request it (https://github.com/o1-labs/proof-systems/issues)");
                        } else if path.is_ident("auxiliary_type") {
                            helper_attributes.auxiliary_type = Some(value);
                            panic!("`auxiliary_type` is not supported yet. Post an issue with this error to request it (https://github.com/o1-labs/proof-systems/issues)");
                        } else if path.is_ident("value") {
                            helper_attributes.value = Some(value);
                        } else {
                            panic!("{malformed_snarky_helper}");
                        }
                    }
                    x => panic!("{x:?} {malformed_snarky_helper}"),
                };
            }
        }
    }

    // enforce that custom auxiliary type and custom auxiliary fn come hand in hand
    match (
        helper_attributes.auxiliary_type.is_some(),
        helper_attributes.auxiliary_fn.is_some(),
    ) {
        (true, false) | (false, true) => {
            panic!("`auxiliary_type` and `auxiliary_fn` have to be specified together")
        }
        _ => (),
    };

    // enforce that we have a type parameter `F: PrimeField`
    // this is needed as we use the same type parameter in the implementation of SnarkyType
    // (i.e. `impl<F> SnarkyType<F> for MyType<F, _>`)
    //
    // Note: if you use `#[snarky(field = "MyField")]`, then we don't enforce this

    let has_f_primefield = |generic: &WherePredicate| {
        if let WherePredicate::Type(t) = generic {
            // check that the type parameter is `F`
            if !matches!(&t.bounded_ty, Type::Path(p) if p.path.is_ident("F")) {
                return false;
            }
            // check that it is bound by `PrimeField`
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

    let missing_field_err =
        "SnarkyType requires the type to have a type parameter `F: PrimeField, or to specify the field used via `#[snarky(field = \"...\")]`";

    let has_f_primefield = item_struct
        .generics
        .where_clause
        .as_ref()
        .map(|w| w.predicates.iter().any(has_f_primefield))
        .unwrap_or(false);

    let impl_field = match (has_f_primefield, helper_attributes.field.as_ref()) {
        (true, None) => "F",
        (false, Some(field)) => field,
        (false, None) => panic!("{missing_field_err}"),
        (true, Some(_)) => panic!("you cannot specify a field via `#[snarky(field = \"...\")] if the type already has a `F: PrimeField`"),  
    };
    let impl_field_path: syn::Path = syn::parse_str(impl_field).unwrap();

    // collect field names and types
    let fields = &item_struct.fields;
    let (field_names, field_types) = match fields {
        Fields::Named(fields) => fields
            .named
            .iter()
            .map(|f| (f.ident.as_ref().unwrap(), &f.ty))
            .unzip(),
        Fields::Unnamed(_fields) => panic!("tuple structs are not supported yet"),
        Fields::Unit => (vec![], vec![]),
    };

    // enforce that we have at least 1 field
    if field_names.is_empty() {
        panic!("to use `#[derive(SnarkyType)]` your struct must at least have one field");
    }

    // this deriver is used by both external users, and the kimchi crate itself,
    // so we need to change the path to kimchi depending on the context
    let lib_path = if std::env::var("CARGO_PKG_NAME").unwrap() == "kimchi" {
        "crate"
    } else {
        "::kimchi"
    };
    let snarky_type_path_str = format!("{lib_path}::SnarkyType<{impl_field}>");
    let snarky_type_path: syn::Path = syn::parse_str(&snarky_type_path_str).unwrap();

    //
    // We define every block of the SnarkyType implementation individually.
    //

    let auxiliary = if field_names.len() > 1 {
        quote! {
            type Auxiliary = (
                #( <#field_types as #snarky_type_path>::Auxiliary ),*
            );
        }
    } else {
        quote! {
            type Auxiliary = (
                #( <#field_types as #snarky_type_path>::Auxiliary )*
            );
        }
    };

    let out_of_circuit = if let Some(value) = &helper_attributes.value {
        let typ: syn::Path = syn::parse_str(value).expect("could not parse your value");
        quote! {
            type OutOfCircuit = #typ;
        }
    } else if field_names.len() > 1 {
        quote! {
            type OutOfCircuit = (
                #( <#field_types as #snarky_type_path>::OutOfCircuit ),*
            );
        }
    } else {
        quote! {
            type OutOfCircuit = (
                #( <#field_types as #snarky_type_path>::OutOfCircuit )*
            );
        }
    };

    let size_in_field_elements = quote! {
        const SIZE_IN_FIELD_ELEMENTS: usize = #( <#field_types as #snarky_type_path>::SIZE_IN_FIELD_ELEMENTS )+*;
    };

    let to_cvars = if field_names.len() > 1 {
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
            fn to_cvars(&self) -> (Vec<FieldVar<#impl_field_path>>, Self::Auxiliary) {
                let mut cvars = Vec::with_capacity(Self::SIZE_IN_FIELD_ELEMENTS);

                #( #to_cvars_calls );*

                let aux = (
                    #( #aux ),*
                );

                (cvars, aux)
            }
        }
    } else {
        quote! {
            fn to_cvars(&self) -> (Vec<FieldVar<#impl_field_path>>, Self::Auxiliary) {
                #( self.#field_names.to_cvars() )*
            }
        }
    };

    let from_cvars_unsafe = if field_names.len() > 1 {
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
            fn from_cvars_unsafe(cvars: Vec<FieldVar<#impl_field_path>>, aux: Self::Auxiliary) -> Self {
                assert_eq!(cvars.len(), Self::SIZE_IN_FIELD_ELEMENTS);

                let mut offset = 0;
                #( #cvars_and_aux );*

                Self {
                    #( #field_names: #from_cvars_unsafe ),*
                }
            }
        }
    } else {
        quote! {
            fn from_cvars_unsafe(cvars: Vec<FieldVar<#impl_field_path>>, aux: Self::Auxiliary) -> Self {
                assert_eq!(cvars.len(), Self::SIZE_IN_FIELD_ELEMENTS);

                Self {
                    #( #field_names: <#field_types as #snarky_type_path>::from_cvars_unsafe(cvars, aux) ),*
                }
            }
        }
    };

    let check = {
        quote! {
            fn check(&self, cs: &mut RunState<#impl_field_path>) -> SnarkyResult<()> {
                #( self.#field_names.check(cs)? );*
                Ok(())
            }
        }
    };

    // constraint_system_auxiliary
    let constraint_system_auxiliary = if field_names.len() > 1 {
        quote! {
            fn constraint_system_auxiliary() -> Self::Auxiliary {
                (
                    #( <#field_types as #snarky_type_path>::constraint_system_auxiliary() ),*
                )
            }
        }
    } else {
        quote! {
            fn constraint_system_auxiliary() -> Self::Auxiliary {
                (
                    #( <#field_types as #snarky_type_path>::constraint_system_auxiliary() )*
                )
            }
        }
    };

    // value_to_field_elements
    let value_to_field_elements = if helper_attributes.value.is_some() {
        let value_trait = format!("{lib_path}::CircuitAndValue<{impl_field}>");
        let value_trait: syn::Path = syn::parse_str(&value_trait).unwrap();
        quote! {
            fn value_to_field_elements(value: &Self::OutOfCircuit) -> (Vec<#impl_field_path>, Self::Auxiliary) {
                <Self as #value_trait>::from_value(value)
            }
        }
    } else if field_names.len() > 1 {
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
            fn value_to_field_elements(value: &Self::OutOfCircuit) -> (Vec<#impl_field_path>, Self::Auxiliary) {
                #( #value_to_field_elements_calls );*

                let fields = [ #( #fields_i ),* ].concat();

                let aux = (
                    #( #aux_i ),*
                );

                (fields, aux)
            }
        }
    } else {
        quote! {
            fn value_to_field_elements(value: &Self::OutOfCircuit) -> (Vec<#impl_field_path>, Self::Auxiliary) {

                #( <#field_types as #snarky_type_path>::value_to_field_elements(value) )*
            }
        }
    };

    // value_of_field_elements
    let value_of_field_elements = if helper_attributes.value.is_some() {
        let value_trait = format!("{lib_path}::CircuitAndValue<{impl_field}>");
        let value_trait: syn::Path = syn::parse_str(&value_trait).unwrap();

        quote! {
            fn value_of_field_elements(fields: Vec<#impl_field_path>, aux: Self::Auxiliary) -> Self::OutOfCircuit {
                assert_eq!(fields.len(), Self::SIZE_IN_FIELD_ELEMENTS);
                <Self as #value_trait>::to_value(fields, aux)
            }
        }
    } else if field_types.len() > 1 {
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
            fn value_of_field_elements(fields: Vec<#impl_field_path>, aux: Self::Auxiliary) -> Self::OutOfCircuit {
                assert_eq!(fields.len(), Self::SIZE_IN_FIELD_ELEMENTS);

                let mut offset = 0;
                #( #fields_and_aux );*

                (
                    #( #value_of_field_elements ),*
                )
            }
        }
    } else {
        quote! {
            fn value_of_field_elements(fields: Vec<#impl_field_path>, aux: Self::Auxiliary) -> Self::OutOfCircuit {
                assert_eq!(fields.len(), Self::SIZE_IN_FIELD_ELEMENTS);

                #( <#field_types as #snarky_type_path>::value_of_field_elements(fields, aux) )*
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
        syn::parse_str(&snarky_type_path_str).expect("snarky_type_path_str is not a valid?");
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
            Type::Array(array) => types_to_bind.insert(*array.elem.clone()),
            x => panic!("non-path as bound types are not supported yet. To request this feature, please copy the entire error to a Github issue (https://github.com/o1-labs/proof-systems): {x:?}"),
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
    let name = &item_struct.ident;
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
