// testing the single tuple edge-case
// this should compile to single_tuple = { inner: string } instead of single_tuple = string

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
