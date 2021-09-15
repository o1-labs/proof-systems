extern crate proc_macro;
use convert_case::{Case, Casing};
use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use quote::quote;
use syn::{Fields, GenericArgument, GenericParam, PathArguments, Type};

//
// ```
// #[ocaml_gen]
// pub fn something(arg1: ...) { ... }
// ```
//

// TODO: will we run into issue with ordering of macro? for example with ocaml::func?
// (https://github.com/rust-lang/rust/issues/67839#issuecomment-570652165)
#[proc_macro_attribute]
pub fn ocaml_gen(attribute: TokenStream, item: TokenStream) -> TokenStream {
    let mut item_fn: syn::ItemFn = syn::parse(item).unwrap();
    let new_fn = quote! {
        pub fn hello() {
            println!("hello world");
        }
    };
    let gen = quote! {
        #item_fn
        #new_fn
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

/// removes Caml prefix
fn strip_caml(ident: String) -> String {
    ident
        .strip_suffix("caml_")
        .map(|x| x.to_string())
        .unwrap_or(ident)
}

/// translation between Rust native types and OCaml native types
fn rust_native_to_ocaml(ty: String) -> String {
    match ty.as_ref() {
        "Vec" => "array".to_string(),
        _ => ty,
    }
}

/// Converts a Rust type into an OCaml type, when parsing AST
fn rust_type_to_ocaml(generics: &[String], ty: &Type) -> String {
    match ty {
        Type::Array(x) => panic!("rust_type_to_ocaml: array"),
        Type::BareFn(x) => panic!("rust_type_to_ocaml: barefn"),
        Type::Group(x) => panic!("rust_type_to_ocaml: group"),
        Type::ImplTrait(x) => panic!("rust_type_to_ocaml: impltrait"),
        Type::Infer(x) => panic!("rust_type_to_ocaml: infer"),
        Type::Macro(x) => panic!("rust_type_to_ocaml: macro"),
        Type::Never(x) => panic!("rust_type_to_ocaml: never"),
        Type::Paren(x) => panic!("rust_type_to_ocaml: paren"),
        Type::Path(p) => {
            assert_eq!(
                p.path.segments.len(),
                1,
                "import a type if it is used in a struct"
            );
            let p = &p.path.segments[0];
            let mut ident = p.ident.to_string();
            if generics.contains(&ident) {
                ident = format!("'{}", rust_ident_to_ocaml(ident));
            } else {
                ident = rust_native_to_ocaml(ident);
                ident = rust_ident_to_ocaml(ident);
            }

            let generics: Vec<_> = match &p.arguments {
                PathArguments::AngleBracketed(a) => a
                    .args
                    .iter()
                    .filter_map(|g| match g {
                        GenericArgument::Lifetime(_) => None,
                        GenericArgument::Type(ty) => {
                            let ident = rust_type_to_ocaml(generics, ty).to_string();
                            Some(ident)
                        }
                        GenericArgument::Binding(_) => panic!("rust_type_to_ocaml: binding"),
                        GenericArgument::Constraint(_) => panic!("rust_type_to_ocaml: constraint"),
                        GenericArgument::Const(_) => panic!("rust_type_to_ocaml: const"),
                    })
                    .collect(),
                PathArguments::None => vec![],
                _ => {
                    println!("path argument: {:#?}", p.arguments);
                    panic!("rust_type_to_ocaml: PathArgument not supported")
                }
            };

            let generics = if generics.len() == 0 {
                "".to_string()
            } else {
                format!("({})", generics.join(", "))
            };

            format!("{} {}", generics, ident)
        }
        Type::Ptr(x) => panic!("rust_type_to_ocaml: ptr"),
        Type::Reference(x) => panic!("rust_type_to_ocaml: reference"),
        Type::Slice(x) => panic!("rust_type_to_ocaml: slice"),
        Type::TraitObject(x) => panic!("rust_type_to_ocaml: traitobject"),
        Type::Tuple(t) => {
            let t: Vec<_> = t
                .elems
                .iter()
                .map(|e| rust_type_to_ocaml(generics, e))
                .collect();
            t.join(" * ")
        }
        Type::Verbatim(x) => panic!("rust_type_to_ocaml: verbatim"),
        _ => panic!("rust_type_to_ocaml: unknown type"),
    }
}

#[proc_macro_derive(OcamlGen)]
pub fn derive_ocaml_gen(item: TokenStream) -> TokenStream {
    let item_struct =
        syn::parse::<syn::ItemStruct>(item).expect("only structs are supported at the moment");
    let name = &item_struct.ident;
    let generics = &item_struct.generics.params;
    let fields = &item_struct.fields;

    let ocaml = {
        let name = rust_ident_to_ocaml(name.to_string());
        let generics: Vec<_> = generics
            .iter()
            .filter_map(|g| match g {
                GenericParam::Type(t) => Some(&t.ident),
                _ => None,
            })
            .map(|ident| ident.to_string())
            .collect();

        let body = match fields {
            Fields::Named(fields) => {
                let fields: Vec<_> = fields
                    .named
                    .iter()
                    .map(|g| {
                        let name = g.ident.as_ref().expect("a named field has an ident");
                        let ty = rust_type_to_ocaml(&generics, &g.ty);
                        return format!("{}: {}", name, ty);
                    })
                    .collect();
                format!("{{ {} }}", fields.join("; "))
            }
            Fields::Unnamed(fields) => {
                let fields: Vec<_> = fields
                    .unnamed
                    .iter()
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
                    .map(|g| rust_type_to_ocaml(&generics, &g.ty))
                    .collect();
                fields.join(" * ")
            }
            _ => panic!("only named, and unnamed field supported"),
        };

        let generics = {
            if generics.len() == 0 {
                "".to_string()
            } else {
                let generics: Vec<_> = generics
                    .into_iter()
                    .map(|g| format!("'{}", rust_ident_to_ocaml(g)))
                    .collect();
                format!("({})", generics.join(", "))
            }
        };

        format!("type {} {} = {}", generics, name, body)
    };

    let fn_name = Ident::new(&format!("{}_to_ocaml", name), Span::call_site());

    let gen = quote! {
        pub fn #fn_name( ) -> &'static str {
            #ocaml
        }
    };

    gen.into()

    /*
    let name = &item_fn.sig.ident;
    let unsafety = &item_fn.sig.unsafety;
    let constness = &item_fn.sig.constness;
    let mut gc_name = syn::Ident::new("gc", name.span());
    let mut use_gc = quote!({let _ = &#gc_name;});
    if let Ok(ident) = syn::parse::<syn::Ident>(attribute) {
        gc_name = ident;
        use_gc = quote!();
    }

    //////// my code ///////

    //////// end of my code //////

    let (returns, rust_return_type) = match &item_fn.sig.output {
        syn::ReturnType::Default => (false, None),
        syn::ReturnType::Type(_, t) => (true, Some(t)),
    };

    let rust_args: Vec<_> = item_fn.sig.inputs.iter().collect();

    let args: Vec<_> = item_fn
        .sig
        .inputs
        .iter()
        .map(|arg| match arg {
            syn::FnArg::Receiver(_) => panic!("OCaml functions cannot take a self argument"),
            syn::FnArg::Typed(t) => match t.pat.as_ref() {
                syn::Pat::Ident(ident) => Some(ident),
                _ => None,
            },
        })
        .collect();

    let mut ocaml_args: Vec<_> = args
        .iter()
        .map(|t| match t {
            Some(ident) => {
                let ident = &ident.ident;
                quote! { #ident: ocaml::Raw }
            }
            None => quote! { _: ocaml::Raw },
        })
        .collect();

    let param_names: syn::punctuated::Punctuated<syn::Ident, syn::token::Comma> = args
        .iter()
        .filter_map(|arg| match arg {
            Some(ident) => Some(ident.ident.clone()),
            None => None,
        })
        .collect();

    let convert_params: Vec<_> = args
        .iter()
        .filter_map(|arg| match arg {
            Some(ident) => {
                let ident = ident.ident.clone();
                Some(quote! { let #ident = ocaml::FromValue::from_value(unsafe { ocaml::Value::new(#ident) }); })
            }
            None => None,
        })
        .collect();

    if ocaml_args.is_empty() {
        ocaml_args.push(quote! { _: ocaml::Raw});
    }

    let body = &item_fn.block;

    let inner = if returns {
        quote! {
            #[inline(always)]
            #constness #unsafety fn inner(#gc_name: &mut ocaml::Runtime, #(#rust_args),*) -> #rust_return_type {
                #use_gc
                #body
            }
        }
    } else {
        quote! {
            #[inline(always)]
            #constness #unsafety fn inner(#gc_name: &mut ocaml::Runtime, #(#rust_args),*)  {
                #use_gc
                #body
            }
        }
    };

    let where_clause = &item_fn.sig.generics.where_clause;
    let attr: Vec<_> = item_fn.attrs.iter().collect();

    // for code generation, we need to do that:
    let func_name = name.to_string();
    let submit = quote! {
        inventory::submit! {
            OcamlFunc::new(module_path!(), #func_name, vec!["t: int"])
        }
    };

    let gen = quote! {
        #submit

        #[no_mangle]
        #(
            #attr
        )*
        pub #constness #unsafety extern "C" fn #name(#(#ocaml_args),*) -> ocaml::Raw #where_clause {
            #inner

            ocaml::body!(#gc_name: {
                #(#convert_params);*
                let res = inner(#gc_name, #param_names);
                #[allow(unused_unsafe)]
                let mut gc_ = unsafe { ocaml::Runtime::recover_handle() };
                unsafe { ocaml::IntoValue::into_value(res, &gc_).raw() }
            })
        }
    };
    */
}

/*
// TODO: is this needed?
pub use inventory;

pub struct OcamlModule {
    pub module: &'static str,
    pub content: OcamlContent,
}

inventory::collect!(OcamlModule);

pub enum OcamlContent {
    Type(OcamlType),
    Func(OcamlFunc),
}

//
// OCaml types
//

/// A representation of an OCaml type
pub enum OcamlType {
    /// A struct
    Struct {
        name: &'static str,
        generics: Vec<&'static str>,
        fields: Vec<(&'static str, Box<OcamlType>)>,
    },
    /// The unit type
    Unit,
    /// A tuple of types
    Tuple(Vec<Box<OcamlType>>),
    /// A string
    String,
    /// An int
    Int,
    /// A vec of types
    Vec(Vec<Box<OcamlType>>),
    /// A type we don't know more about
    Type {
        name: &'static str,
        generics: Vec<&'static str>,
    },
}

/*

#[macro_export]
macro_rules! ocaml_type {
    ($module:tt, $generics:tt, $fields:tt) => {
        inventory::submit! {
            crate::ocaml_gen::OcamlType {
                module: $module,
                name: "",
                generics: $generics,
                fields: $fields,
            }
        }
    };
}

pub(crate) use ocaml_type;

*/

//
// OCaml functions
//

/// A representation of an OCaml function
pub struct OcamlFunc {
    pub module: &'static str,
    pub name: &'static str,
    pub args: Vec<&'static str>,
}

impl OcamlFunc {
    pub fn new(module: &'static str, name: &'static str, args: Vec<&'static str>) -> Self {
        OcamlFunc { module, name, args }
    }
}
/*

#[macro_export]
macro_rules! ocaml_func {
    ($ty:tt) => {
        inventory::submit! {
            crate::ocaml_gen::OcamlFunc::new($ty, "test init", vec!["t: int"])
        }
    };
}

pub(crate) use ocaml_func;
*/

//
// Generation of OCaml code
//

pub struct OcamlFile {}

impl OcamlFile {
    fn gen_module(ocaml_module: &OcamlModule) -> String {
        let module = ocaml_module.module;
        let content = match &ocaml_module.content {
            OcamlContent::Type(ty) => OcamlFile::gen_type(&ty),
            OcamlContent::Func(_) => panic!(),
        };
        format!(r#"module {} = struct {} end"#, module, content,)
    }

    fn gen_type(ty: &OcamlType) -> String {
        match ty {
            OcamlType::Struct {
                name,
                generics,
                fields,
            } => {
                let generics: Vec<_> = generics.iter().map(|g| format!("'{}", g)).collect();

                let fields: Vec<_> = fields
                    .iter()
                    .map(|(ident, ty)| format!("{}: {}", ident, Self::gen_type(ty)))
                    .collect();

                format!(
                    r#"type {} {} = {{ {} }}"#,
                    generics.join(" "),
                    name,
                    fields.join("; ")
                )
            }
            OcamlType::Unit => "()".to_string(),
            OcamlType::Tuple(v) => {
                let fields: Vec<_> = v.iter().map(|ty| Self::gen_type(ty)).collect();
                format!("({})", fields.join(", "))
            }
            OcamlType::String => "string".to_string(),
            OcamlType::Int => "int".to_string(),
            OcamlType::Vec(v) => {
                let fields: Vec<_> = v.iter().map(|ty| Self::gen_type(ty)).collect();
                format!("{} array", fields.join(", "))
            }
            OcamlType::Type { name, generics } => {
                let generics: Vec<_> = generics.iter().map(|g| format!("'{}", g)).collect();
                format!("{} {}", generics.join(" "), name)
            }
        }
    }

    pub fn gen_ocaml_bindings() {
        for m in inventory::iter::<OcamlModule> {
            println!("{}", Self::gen_module(m));
        }
    }
}
*/
