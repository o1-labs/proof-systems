#[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::OcamlGen)]
pub struct SingleTuple(String);

#[ocaml_gen::ocaml_gen]
#[ocaml::func]
pub fn new() -> SingleTuple {
    SingleTuple(String::from("Hello"))
}

#[ocaml_gen::ocaml_gen]
#[ocaml::func]
pub fn print(s: SingleTuple) {
    println!("{}", s.0);
}
