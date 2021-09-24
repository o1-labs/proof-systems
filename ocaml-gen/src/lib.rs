// TODO: get rid of nightly with https://github.com/dtolnay/paste ?

//! Some doc is needed here.
//!
//! ```
//! // the bindings are printed out for now
//! println!("(* this file is generated automatically *)\n");
//!
//! // initialize your environment
//! let env = &mut Env::default();
//!
//! // we need to create fake generic placeholders for generic structs
//! decl_fake_generic!(T1, 0);
//! decl_fake_generic!(T2, 1);
//!
//! // declare a module Types containing a bunch of types
//! decl_module!(env, "Types", {
//!     decl_type!(env, CamlScalarChallenge::<T1>);
//!     // you can also rename a type
//!     decl_type!(env, CamlRandomOracles::<T1> => "random_oracles");
//! });
//!
//! decl_module!(env, "BigInt256", {
//!     decl_type!(env, CamlBigInteger256 => "t");
//!     // you will have to import all (*) so that this can find
//!     // the underlying function called `caml_of_numeral_to_ocaml`
//!     decl_func!(env, caml_of_numeral => "of_numeral");
//! });
//! ```
//!

extern crate ocaml_derive;
use std::collections::{hash_map::Entry, HashMap};

pub use const_random::const_random;
use convert_case::{Case, Casing};
pub use ocaml_derive::*;

pub mod conv;

//
// Structs
//

/// The environment at some point in time during the declaration of OCaml bindings.
/// It ensures that types cannot be declared twice, and that types that are
/// renamed and/or relocated into module are referenced correctly.
#[derive(Default, Debug)]
pub struct Env {
    /// every type (their path and their name) is stored here at declaration
    locations: HashMap<u128, (Vec<&'static str>, &'static str)>,
    /// the current path we're in (e.g. `ModA.ModB`)
    current_module: Vec<&'static str>,
}

impl Drop for Env {
    /// This makes sure that we close our OCaml modules (with the keyword `end`)
    fn drop(&mut self) {
        if !self.current_module.is_empty() {
            panic!("you must call .root() on the environment to finalize the generation. You are currently still nested: {:?}", self.current_module);
        }
    }
}

impl Env {
    /// Declares a new type. If the type was already declared, this will panic
    pub fn new_type(&mut self, ty: u128, name: &'static str) {
        match self.locations.entry(ty) {
            Entry::Occupied(_) => panic!("ocaml-gen: cannot re-declare the same type twice"),
            Entry::Vacant(v) => v.insert((self.current_module.clone(), name)),
        };
    }

    /// retrieves a type that was declared previously
    pub fn get_type(&self, ty: u128) -> String {
        let (type_path, type_name) = self
            .locations
            .get(&ty)
            // not a great error, I know
            .expect("ocaml-gen: the type hasn't been declared");

        let type_path = type_path.join(".");
        let current_module = self.current_module.join(".");
        if type_path == current_module {
            type_name.to_string()
        } else {
            format!("{}.{}", type_path, type_name)
        }
    }

    /// create a module and enters it
    pub fn new_module(&mut self, mod_name: &'static str) -> String {
        let camelized = mod_name.to_case(Case::Pascal); // Pascal = CamelCase
        if camelized != mod_name {
            panic!(
                "ocaml-gen: OCaml uses CamelCase for module names, you provided: {}, and we expected: {}", mod_name, camelized
            );
        }

        self.current_module.push(mod_name);
        format!("module {} = struct ", mod_name)
    }

    /// go back up one module
    pub fn parent(&mut self) -> String {
        self.current_module
            .pop()
            .expect("ocaml-gen: you are already at the root");
        "end".to_string()
    }

    /// you can call this to go back to the root and finalize the generation
    pub fn root(&mut self) -> String {
        let mut res = String::new();
        for _ in &self.current_module {
            res.push_str("end\n");
        }
        res
    }
}

//
// Traits
//

/// OCamlBinding is the trait implemented by types to generate their OCaml bindings.
/// It is usually derived automatically via the [OcamlGen] macro,
/// or the [OCamlCustomType] macro for custom types.
/// For functions, refer to the [ocaml_gen] macro.
pub trait OCamlBinding {
    /// will generate the OCaml bindings for a type (called root type).
    /// It takes the current environment [Env],
    /// as well as an optional name (if you wish to rename the type in OCaml).
    fn ocaml_binding(env: &mut Env, rename: Option<&'static str>) -> String;
}

/// OCamlDesc is the trait implemented by types to facilitate generation of their OCaml bindings.
/// It is usually derived automatically via the [OcamlGen] macro,
/// or the [OCamlCustomType] macro for custom types.
pub trait OCamlDesc {
    /// describes the type in OCaml, given the current environment [Env]
    /// and the list of generic type parameters of the root type
    /// (the type that makes use of this type)
    fn ocaml_desc(env: &Env, generics: &[&str]) -> String;

    /// Returns a unique ID for the type. This ID will not change if concrete type parameters are used.
    fn unique_id() -> u128;
}

//
// Func-like macros
//

/// Creates a module
#[macro_export]
macro_rules! decl_module {
    ($env:expr, $name:expr, $b:block) => {{
        println!("{}", $env.new_module($name));
        $b
        println!("{}", $env.parent());
    }}
}

/// Declares the binding for a given function
#[macro_export]
macro_rules! decl_func {
    ($env:expr, $func:ident) => {{
        let f = concat_idents!($func, _to_ocaml);
        let binding = f($env, None);
        println!("{}", binding);
    }};
    // rename
    ($env:expr, $func:ident => $new:expr) => {{
        let f = concat_idents!($func, _to_ocaml);
        let binding = f($env, Some($new));
        println!("{}", binding);
    }};
}

/// Declares the binding for a given type
#[macro_export]
macro_rules! decl_type {
    ($env:expr, $ty:ty) => {{
        let res = <$ty as ::ocaml_gen::OCamlBinding>::to_binding($env, None);
        println!("{}", res);
    }};
    // rename
    ($env:expr, $ty:ty => $new:expr) => {{
        let res = <$ty as ::ocaml_gen::OCamlBinding>::to_binding($env, Some($new));
        println!("{}", res);
    }};
}

/// Creates a fake generic
#[macro_export]
macro_rules! decl_fake_generic {
    ($name:ident, $i:expr) => {
        pub struct $name;

        impl ::ocaml_gen::OCamlDesc for $name {
            fn ocaml_desc(_env: &::ocaml_gen::Env, generics: &[&str]) -> String {
                format!("'{}", generics[$i])
            }

            fn unique_id() -> u128 {
                ::ocaml_gen::const_random!(u128)
            }
        }
    };
}
