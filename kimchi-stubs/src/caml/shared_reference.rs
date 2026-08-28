//! `impl_shared_reference1` implements an OCaml
//! custom type that wraps around a shared reference to a Rust object.

macro_rules! impl_shared_reference {
    ($name: ident => $typ: ty) => {
        #[derive(Debug, ::ocaml_gen::CustomType)]
        pub struct $name(pub ::std::sync::Arc<$typ>);

        //
        // necessary ocaml.rs stuff
        //

        impl $name {
            extern "C" fn caml_pointer_finalize(v: ::ocaml::Raw) {
                unsafe {
                    let v: ::ocaml::Pointer<Self> = v.as_pointer();
                    v.drop_in_place();
                }
            }

            extern "C" fn caml_pointer_compare(_: ::ocaml::Raw, _: ::ocaml::Raw) -> i32 {
                // Always return equal. We can use this for sanity checks,
                // anything else using this would be broken anyway.
                0
            }

            pub fn new(x: $typ) -> Self {
                Self(::std::sync::Arc::new(x))
            }
        }

        ::ocaml::custom!($name {
            finalize: $name::caml_pointer_finalize,
            compare: $name::caml_pointer_compare,
        });

        // ocaml-rs 1.x dropped the blanket `Custom -> IntoValue` impl and
        // `to_value` now borrows, so hand back a fresh handle sharing the same
        // `Arc`. Deliberately not `#[derive(Clone)]`: these types deref to
        // `Arc<_>`, and an inherent `clone` would silently win method
        // resolution over the inner `Arc::clone` at existing call sites.
        unsafe impl ::ocaml::ToValue for $name {
            fn to_value(&self, rt: &::ocaml::Runtime) -> ::ocaml::Value {
                ::ocaml::Pointer::alloc_custom(Self(::std::sync::Arc::clone(&self.0))).to_value(rt)
            }
        }

        unsafe impl ::ocaml::FromValue for $name {
            fn from_value(value: ::ocaml::Value) -> Self {
                let x: ::ocaml::Pointer<Self> = ::ocaml::FromValue::from_value(value);
                Self(x.as_ref().0.clone())
            }
        }

        //
        // useful implementations
        //

        impl ::core::ops::Deref for $name {
            type Target = ::std::sync::Arc<$typ>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
    };
}
