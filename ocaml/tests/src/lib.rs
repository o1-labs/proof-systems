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

#[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::CustomType)]
pub struct Car {
    name: String,
    doors: usize,
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn create_toyota() -> Car {
    Car {
        name: String::from("Toyota"),
        doors: 4,
    }
}
