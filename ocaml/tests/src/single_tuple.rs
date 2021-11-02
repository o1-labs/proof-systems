#[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
pub struct SingleTuple(String);

#[ocaml_gen::func]
#[ocaml::func]
pub fn new() -> SingleTuple {
    SingleTuple(String::from("Hello"))
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn print(s: SingleTuple) {
    println!("{}", s.0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ocaml_gen::{decl_type, Env};
    use std::fmt::Write;

    const SHOULD_COMPILE_TO: &str = "type nonrec single_tuple = { inner: string } [@@boxed]";

    #[test]
    fn test_tupple() {
        let mut w = String::new();
        let env = &mut Env::default();
        decl_type!(w, env, SingleTuple);
        assert_eq!(SHOULD_COMPILE_TO, w.trim());
    }
}
