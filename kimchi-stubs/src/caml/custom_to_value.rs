//! Restores, per type, the conversion that `ocaml-rs` 0.22 provided for free.
//!
//! 0.22 carried a blanket `unsafe impl<T: 'static + Custom> IntoValue for T`,
//! so any custom type could be returned straight to OCaml. 1.x dropped it —
//! `Pointer<T>` is the only thing that converts now — and the orphan rule stops
//! us from reinstating the blanket impl here, since both `Custom` and
//! `ToValue` are foreign. So each custom type opts in explicitly.
//!
//! The type must be `Clone`: `to_value` takes `&self`, but `alloc_custom`
//! needs an owned value to move onto the OCaml heap.
macro_rules! impl_custom_to_value {
    ($name: ty) => {
        unsafe impl ::ocaml::ToValue for $name {
            fn to_value(&self, rt: &::ocaml::Runtime) -> ::ocaml::Value {
                ::ocaml::Pointer::alloc_custom(::core::clone::Clone::clone(self)).to_value(rt)
            }
        }
    };
}
