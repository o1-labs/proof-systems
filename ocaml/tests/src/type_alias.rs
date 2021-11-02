#[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
pub struct SomeType<T> {
    t: T,
}

#[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
pub struct SomeOtherType<P, Q> {
    t1: P,
    t2: Q,
}

#[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
pub struct SomeConcreteType {
    s: String,
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn thing() -> SomeType<SomeConcreteType> {
    let t = SomeConcreteType {
        s: "hey".to_string(),
    };
    SomeType { t }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ocaml_gen::{decl_fake_generic, decl_func, decl_module, decl_type, decl_type_alias, Env};
    use std::fmt::Write;

    const SHOULD_COMPILE_TO: &str = r#"type nonrec ('T) t = { t: 'T }
type nonrec ('P, 'Q) some_other_type = { t1: 'P; t2: 'Q }
type nonrec some_concrete_type = { s: string }
module A = struct 
type nonrec t = (some_concrete_type) t
type nonrec t2 = (some_concrete_type, some_concrete_type) some_other_type
external thing : unit -> t = "thing"
end"#;

    #[test]
    fn test_type_alias() {
        let mut w = String::new();
        let env = &mut Env::default();

        decl_fake_generic!(T1, 0);
        decl_fake_generic!(T2, 1);

        decl_type!(w, env, SomeType<T1> => "t");
        decl_type!(w, env, SomeOtherType<T1, T2>);

        decl_type!(w, env, SomeConcreteType);
        decl_module!(w, env, "A", {
            println!("{:?}", env);
            decl_type_alias!(w, env, "t" => SomeType<SomeConcreteType>);
            decl_type_alias!(w, env, "t2" => SomeOtherType<SomeConcreteType, SomeConcreteType>);

            decl_func!(w, env, thing);
        });

        assert_eq!(SHOULD_COMPILE_TO, w.trim());
    }
}
