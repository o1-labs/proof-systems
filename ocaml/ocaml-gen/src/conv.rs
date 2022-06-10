//! Implementations of [crate::OCamlDesc] for types
//! that have natural equivalents in OCaml.

use crate::{Env, OCamlDesc};
use const_random::const_random;

impl OCamlDesc for () {
    fn ocaml_desc(_env: &Env, _generics: &[&str]) -> String {
        "unit".to_string()
    }

    fn unique_id() -> u128 {
        const_random!(u128)
    }
}

impl OCamlDesc for [u8; 32] {
    fn ocaml_desc(_env: &Env, _generics: &[&str]) -> String {
        "bytes".to_string()
    }

    fn unique_id() -> u128 {
        const_random!(u128)
    }
}

impl OCamlDesc for &[u8] {
    fn ocaml_desc(_env: &Env, _generics: &[&str]) -> String {
        "bytes".to_string()
    }

    fn unique_id() -> u128 {
        const_random!(u128)
    }
}

impl<T> OCamlDesc for Vec<T>
where
    T: OCamlDesc,
{
    fn ocaml_desc(env: &Env, generics: &[&str]) -> String {
        format!("({}) array", T::ocaml_desc(env, generics))
    }

    fn unique_id() -> u128 {
        const_random!(u128)
    }
}

impl<T, E> OCamlDesc for Result<T, E>
where
    T: OCamlDesc,
{
    fn ocaml_desc(env: &Env, generics: &[&str]) -> String {
        T::ocaml_desc(env, generics)
    }

    fn unique_id() -> u128 {
        const_random!(u128)
    }
}

impl<T> OCamlDesc for Option<T>
where
    T: OCamlDesc,
{
    fn ocaml_desc(env: &Env, generics: &[&str]) -> String {
        format!("({}) option", T::ocaml_desc(env, generics))
    }

    fn unique_id() -> u128 {
        const_random!(u128)
    }
}

impl OCamlDesc for ocaml::Int {
    fn ocaml_desc(_env: &Env, _generics: &[&str]) -> String {
        "int".to_string()
    }

    fn unique_id() -> u128 {
        const_random!(u128)
    }
}

impl OCamlDesc for String {
    fn ocaml_desc(_env: &Env, _generics: &[&str]) -> String {
        "string".to_string()
    }

    fn unique_id() -> u128 {
        const_random!(u128)
    }
}

impl OCamlDesc for bool {
    fn ocaml_desc(_env: &Env, _generics: &[&str]) -> String {
        "bool".to_string()
    }

    fn unique_id() -> u128 {
        const_random!(u128)
    }
}

impl<T> OCamlDesc for ocaml::Pointer<'_, T>
where
    T: OCamlDesc,
{
    fn ocaml_desc(env: &Env, generics: &[&str]) -> String {
        T::ocaml_desc(env, generics)
    }

    fn unique_id() -> u128 {
        const_random!(u128)
    }
}

impl<T1, T2> OCamlDesc for (T1, T2)
where
    T1: OCamlDesc,
    T2: OCamlDesc,
{
    fn ocaml_desc(env: &Env, generics: &[&str]) -> String {
        let v = vec![T1::ocaml_desc(env, generics), T2::ocaml_desc(env, generics)];
        format!("({})", v.join(" * "))
    }

    fn unique_id() -> u128 {
        const_random!(u128)
    }
}

impl<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15> OCamlDesc
    for (
        T1,
        T2,
        T3,
        T4,
        T5,
        T6,
        T7,
        T8,
        T9,
        T10,
        T11,
        T12,
        T13,
        T14,
        T15,
    )
where
    T1: OCamlDesc,
    T2: OCamlDesc,
    T3: OCamlDesc,
    T4: OCamlDesc,
    T5: OCamlDesc,
    T6: OCamlDesc,
    T7: OCamlDesc,
    T8: OCamlDesc,
    T9: OCamlDesc,
    T10: OCamlDesc,
    T11: OCamlDesc,
    T12: OCamlDesc,
    T13: OCamlDesc,
    T14: OCamlDesc,
    T15: OCamlDesc,
{
    fn ocaml_desc(env: &Env, generics: &[&str]) -> String {
        let v = vec![
            T1::ocaml_desc(env, generics),
            T2::ocaml_desc(env, generics),
            T3::ocaml_desc(env, generics),
            T4::ocaml_desc(env, generics),
            T5::ocaml_desc(env, generics),
            T6::ocaml_desc(env, generics),
            T7::ocaml_desc(env, generics),
            T8::ocaml_desc(env, generics),
            T9::ocaml_desc(env, generics),
            T10::ocaml_desc(env, generics),
            T11::ocaml_desc(env, generics),
            T12::ocaml_desc(env, generics),
            T13::ocaml_desc(env, generics),
            T14::ocaml_desc(env, generics),
            T15::ocaml_desc(env, generics),
        ];
        format!("({})", v.join(" * "))
    }

    fn unique_id() -> u128 {
        const_random!(u128)
    }
}

impl<T1, T2, T3, T4, T5, T6> OCamlDesc for (T1, T2, T3, T4, T5, T6)
where
    T1: OCamlDesc,
    T2: OCamlDesc,
    T3: OCamlDesc,
    T4: OCamlDesc,
    T5: OCamlDesc,
    T6: OCamlDesc,
{
    fn ocaml_desc(env: &Env, generics: &[&str]) -> String {
        let v = vec![
            T1::ocaml_desc(env, generics),
            T2::ocaml_desc(env, generics),
            T3::ocaml_desc(env, generics),
            T4::ocaml_desc(env, generics),
            T5::ocaml_desc(env, generics),
            T6::ocaml_desc(env, generics),
        ];
        format!("({})", v.join(" * "))
    }

    fn unique_id() -> u128 {
        const_random!(u128)
    }
}

impl<T1, T2, T3, T4, T5, T6, T7> OCamlDesc for (T1, T2, T3, T4, T5, T6, T7)
where
    T1: OCamlDesc,
    T2: OCamlDesc,
    T3: OCamlDesc,
    T4: OCamlDesc,
    T5: OCamlDesc,
    T6: OCamlDesc,
    T7: OCamlDesc,
{
    fn ocaml_desc(env: &Env, generics: &[&str]) -> String {
        let v = vec![
            T1::ocaml_desc(env, generics),
            T2::ocaml_desc(env, generics),
            T3::ocaml_desc(env, generics),
            T4::ocaml_desc(env, generics),
            T5::ocaml_desc(env, generics),
            T6::ocaml_desc(env, generics),
            T7::ocaml_desc(env, generics),
        ];
        v.join(" * ")
    }

    fn unique_id() -> u128 {
        const_random!(u128)
    }
}

impl<T1, T2, T3> OCamlDesc for (T1, T2, T3)
where
    T1: OCamlDesc,
    T2: OCamlDesc,
    T3: OCamlDesc,
{
    fn ocaml_desc(env: &Env, generics: &[&str]) -> String {
        let v = vec![
            T1::ocaml_desc(env, generics),
            T2::ocaml_desc(env, generics),
            T3::ocaml_desc(env, generics),
        ];
        format!("({})", v.join(" * "))
    }

    fn unique_id() -> u128 {
        const_random!(u128)
    }
}
