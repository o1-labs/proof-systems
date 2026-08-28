use ocaml::{FromValue, Runtime, ToValue, Value};
use ocaml_gen::{const_random, Env, OCamlDesc};

pub struct CamlBytesString<'a>(pub &'a [u8]);

unsafe impl<'a> ToValue for CamlBytesString<'a> {
    fn to_value(&self, rt: &Runtime) -> Value {
        self.0.to_value(rt)
    }
}

unsafe impl<'a> FromValue for CamlBytesString<'a> {
    fn from_value(v: Value) -> Self {
        CamlBytesString(FromValue::from_value(v))
    }
}

impl<'a> OCamlDesc for CamlBytesString<'a> {
    fn ocaml_desc(_env: &Env, _generics: &[&str]) -> String {
        "string".to_string()
    }

    fn unique_id() -> u128 {
        const_random!(u128)
    }
}
