extern crate ocaml_derive;
pub use ocaml_derive::*;

#[macro_export]
macro_rules! list_types {
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
