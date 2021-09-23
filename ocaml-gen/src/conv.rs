//! Implementations of [crate::ToOcaml] for types
//! that have natural equivalents in OCaml.

use crate::{Env, ToOcaml};
use const_random::const_random;

impl ToOcaml for [u8; 32] {
    fn to_ocaml(env: &Env, _generics: &[&str]) -> String {
        "bytes".to_string()
    }

    fn to_id() -> u128 {
        const_random!(u128)
    }
}

impl ToOcaml for &[u8] {
    fn to_ocaml(env: &Env, _generics: &[&str]) -> String {
        "bytes".to_string()
    }

    fn to_id() -> u128 {
        const_random!(u128)
    }
}

impl<T> ToOcaml for Vec<T>
where
    T: ToOcaml,
{
    fn to_ocaml(env: &Env, generics: &[&str]) -> String {
        format!("{} array", T::to_ocaml(env, generics))
    }

    fn to_id() -> u128 {
        const_random!(u128)
    }
}

impl<T, E> ToOcaml for Result<T, E>
where
    T: ToOcaml,
{
    fn to_ocaml(env: &Env, generics: &[&str]) -> String {
        T::to_ocaml(env, generics)
    }

    fn to_id() -> u128 {
        const_random!(u128)
    }
}

impl<T> ToOcaml for Option<T>
where
    T: ToOcaml,
{
    fn to_ocaml(env: &Env, generics: &[&str]) -> String {
        format!("{} option", T::to_ocaml(env, generics))
    }

    fn to_id() -> u128 {
        const_random!(u128)
    }
}

impl ToOcaml for ocaml::Int {
    fn to_ocaml(_env: &Env, _generics: &[&str]) -> String {
        "int".to_string()
    }

    fn to_id() -> u128 {
        const_random!(u128)
    }
}

impl ToOcaml for String {
    fn to_ocaml(_env: &Env, _generics: &[&str]) -> String {
        "string".to_string()
    }

    fn to_id() -> u128 {
        const_random!(u128)
    }
}

impl ToOcaml for bool {
    fn to_ocaml(_env: &Env, _generics: &[&str]) -> String {
        "bool".to_string()
    }

    fn to_id() -> u128 {
        const_random!(u128)
    }
}

impl<T> ToOcaml for ocaml::Pointer<'_, T>
where
    T: ToOcaml,
{
    fn to_ocaml(env: &Env, generics: &[&str]) -> String {
        T::to_ocaml(env, generics)
    }

    fn to_id() -> u128 {
        const_random!(u128)
    }
}

impl<T1, T2> ToOcaml for (T1, T2)
where
    T1: ToOcaml,
    T2: ToOcaml,
{
    fn to_ocaml(env: &Env, generics: &[&str]) -> String {
        let v = vec![T1::to_ocaml(env, generics), T2::to_ocaml(env, generics)];
        v.join(" * ")
    }

    fn to_id() -> u128 {
        const_random!(u128)
    }
}

impl<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15> ToOcaml
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
    T1: ToOcaml,
    T2: ToOcaml,
    T3: ToOcaml,
    T4: ToOcaml,
    T5: ToOcaml,
    T6: ToOcaml,
    T7: ToOcaml,
    T8: ToOcaml,
    T9: ToOcaml,
    T10: ToOcaml,
    T11: ToOcaml,
    T12: ToOcaml,
    T13: ToOcaml,
    T14: ToOcaml,
    T15: ToOcaml,
{
    fn to_ocaml(env: &Env, generics: &[&str]) -> String {
        let v = vec![
            T1::to_ocaml(env, generics),
            T2::to_ocaml(env, generics),
            T3::to_ocaml(env, generics),
            T4::to_ocaml(env, generics),
            T5::to_ocaml(env, generics),
            T6::to_ocaml(env, generics),
            T7::to_ocaml(env, generics),
            T8::to_ocaml(env, generics),
            T9::to_ocaml(env, generics),
            T10::to_ocaml(env, generics),
            T11::to_ocaml(env, generics),
            T12::to_ocaml(env, generics),
            T13::to_ocaml(env, generics),
            T14::to_ocaml(env, generics),
            T15::to_ocaml(env, generics),
        ];
        v.join(" * ")
    }

    fn to_id() -> u128 {
        const_random!(u128)
    }
}

impl<T1, T2, T3, T4, T5, T6> ToOcaml for (T1, T2, T3, T4, T5, T6)
where
    T1: ToOcaml,
    T2: ToOcaml,
    T3: ToOcaml,
    T4: ToOcaml,
    T5: ToOcaml,
    T6: ToOcaml,
{
    fn to_ocaml(env: &Env, generics: &[&str]) -> String {
        let v = vec![
            T1::to_ocaml(env, generics),
            T2::to_ocaml(env, generics),
            T3::to_ocaml(env, generics),
            T4::to_ocaml(env, generics),
            T5::to_ocaml(env, generics),
            T6::to_ocaml(env, generics),
        ];
        v.join(" * ")
    }

    fn to_id() -> u128 {
        const_random!(u128)
    }
}
