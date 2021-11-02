#[derive(ocaml_gen::CustomType)]
pub struct SomeGenericType<T> {
    #[allow(dead_code)]
    t: T,
}

impl<T> SomeGenericType<T> {
    extern "C" fn finalize(v: ocaml::Raw) {
        unsafe {
            let mut v: ocaml::Pointer<Self> = v.as_pointer();
            v.as_mut_ptr().drop_in_place();
        }
    }
}

ocaml::custom!(SomeGenericType<T> {
    finalize: SomeGenericType::<T>::finalize,
});

#[cfg(test)]
mod tests {
    use super::*;
    use ocaml_gen::{decl_fake_generic, decl_type, decl_type_alias, Env};
    use std::fmt::Write;

    const SHOULD_COMPILE_TO: &str = r#"type some_generic_type"#;

    #[test]
    #[should_panic]
    fn test_double_custom_definition() {
        let mut w = String::new();
        let env = &mut Env::default();

        decl_fake_generic!(T1, 0);

        decl_type!(w, env, SomeGenericType<T1>);

        decl_type!(w, env, SomeGenericType<T1>);
    }

    #[test]
    #[should_panic]
    fn test_alias_of_custom() {
        let mut w = String::new();
        let env = &mut Env::default();

        decl_fake_generic!(T1, 0);

        decl_type!(w, env, SomeGenericType<T1>);

        decl_type_alias!(w, env, "t2" => SomeGenericType<T1>);
    }

    #[test]
    fn test_generic_custom_type() {
        let mut w = String::new();
        let env = &mut Env::default();

        decl_fake_generic!(T1, 0);

        decl_type!(w, env, SomeGenericType<T1>);

        assert_eq!(SHOULD_COMPILE_TO, w.trim());
    }
}
