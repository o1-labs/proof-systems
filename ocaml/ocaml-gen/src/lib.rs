#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

extern crate ocaml_derive;
use std::collections::{hash_map::Entry, HashMap};

pub use const_random::const_random;
pub use ocaml_derive::*;
pub use paste::paste;

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
    /// Declares a new type. If the type was already declared, this will panic. If you are declaring a custom type, use [new_custom_type].
    pub fn new_type(&mut self, ty: u128, name: &'static str) {
        match self.locations.entry(ty) {
            Entry::Occupied(_) => panic!("ocaml-gen: cannot re-declare the same type twice"),
            Entry::Vacant(v) => v.insert((self.current_module.clone(), name)),
        };
    }

    /// retrieves a type that was declared previously
    pub fn get_type(&self, ty: u128, name: &str) -> String {
        let (type_path, type_name) = self
            .locations
            .get(&ty)
            .unwrap_or_else(|| panic!("ocaml-gen: the type {} hasn't been declared", name));

        // path resolution
        let mut current = self.current_module.clone();
        current.reverse();
        let path: Vec<&str> = type_path
            .iter()
            .skip_while(|&p| Some(*p) == current.pop())
            .copied()
            .collect();

        if path.is_empty() {
            type_name.to_string()
        } else {
            format!("{}.{}", path.join("."), type_name)
        }
    }

    /// create a module and enters it
    pub fn new_module(&mut self, mod_name: &'static str) -> String {
        let first_letter = mod_name
            .chars()
            .next()
            .expect("module name cannot be empty");
        if first_letter.to_uppercase().to_string() != first_letter.to_string() {
            panic!(
                "ocaml-gen: OCaml module names start with an uppercase, you provided: {}",
                mod_name
            );
        }

        self.current_module.push(mod_name);
        format!("module {} = struct ", mod_name)
    }

    /// how deeply nested are we currently? (default is 0)
    pub fn nested(&self) -> usize {
        self.current_module.len()
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
/// It is usually derived automatically via the [Struct] macro,
/// or the [CustomType] macro for custom types.
/// For functions, refer to the [func] macro.
pub trait OCamlBinding {
    /// will generate the OCaml bindings for a type (called root type).
    /// It takes the current environment [Env],
    /// as well as an optional name (if you wish to rename the type in OCaml).
    fn ocaml_binding(env: &mut Env, rename: Option<&'static str>, new_type: bool) -> String;
}

/// OCamlDesc is the trait implemented by types to facilitate generation of their OCaml bindings.
/// It is usually derived automatically via the [Struct] macro,
/// or the [CustomType] macro for custom types.
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
    ($w:expr, $env:expr, $name:expr, $b:block) => {{
        use std::io::Write;
        write!($w, "\n{}{}\n", format_args!("{: >1$}", "", $env.nested() * 2), $env.new_module($name)).unwrap();
        $b
        write!($w, "{}{}\n\n", format_args!("{: >1$}", "", $env.nested() * 2 - 2), $env.parent()).unwrap();
    }}
}

/// Declares the binding for a given function
#[macro_export]
macro_rules! decl_func {
    ($w:expr, $env:expr, $func:ident) => {{
        use std::io::Write;
        ::ocaml_gen::paste! {
            let binding = [<$func _to_ocaml>]($env, None);
        }
        write!(
            $w,
            "{}{}\n",
            format_args!("{: >1$}", "", $env.nested() * 2),
            binding,
        )
        .unwrap();
    }};
    // rename
    ($w:expr, $env:expr, $func:ident => $new:expr) => {{
        use std::io::Write;
        ::ocaml_gen::paste! {
            let binding = [<$func _to_ocaml>]($env, Some($new));
        }
        write!(
            $w,
            "{}{}\n",
            format_args!("{: >1$}", "", $env.nested() * 2),
            binding,
        )
        .unwrap();
    }};
}

/// Declares the binding for a given type
#[macro_export]
macro_rules! decl_type {
    ($w:expr, $env:expr, $ty:ty) => {{
        use std::io::Write;
        let res = <$ty as ::ocaml_gen::OCamlBinding>::ocaml_binding($env, None, true);
        write!(
            $w,
            "{}{}\n",
            format_args!("{: >1$}", "", $env.nested() * 2),
            res,
        )
        .unwrap();
    }};
    // rename
    ($w:expr, $env:expr, $ty:ty => $new:expr) => {{
        use std::io::Write;
        let res = <$ty as ::ocaml_gen::OCamlBinding>::ocaml_binding($env, Some($new), true);
        write!(
            $w,
            "{}{}\n",
            format_args!("{: >1$}", "", $env.nested() * 2),
            res,
        )
        .unwrap();
    }};
}

/// Declares a new OCaml type that is made of other types
#[macro_export]
macro_rules! decl_type_alias {
    ($w:expr, $env:expr, $new:expr => $ty:ty) => {{
        use std::io::Write;
        let res = <$ty as ::ocaml_gen::OCamlBinding>::ocaml_binding($env, Some($new), false);
        write!(
            $w,
            "{}{}\n",
            format_args!("{: >1$}", "", $env.nested() * 2),
            res,
        )
        .unwrap();
    }};
}

/// Creates a fake generic. This is a necessary hack, at the moment, to declare types (with the [decl_type] macro) that have generic parameters.
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
