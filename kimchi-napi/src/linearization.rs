//! The linearization token streams for the `fp/fq_linearization_tokens`
//! OCaml externals, mirroring the JS-facing API of `kimchi-wasm`. The tokens
//! cross the FFI as one JSON string in the js_of_ocaml encoding produced by
//! [`kimchi::linearization_tokens`]; the JS side
//! (`kimchi_bindings/js/bindings/linearization.js`) decodes it.

use kimchi::linearization_tokens::linearization_tokens_ocaml_json;
use napi_derive::napi;

#[napi(js_name = "fp_linearization_tokens")]
pub fn fp_linearization_tokens() -> String {
    linearization_tokens_ocaml_json::<mina_curves::pasta::Fp>(true)
}

#[napi(js_name = "fq_linearization_tokens")]
pub fn fq_linearization_tokens() -> String {
    linearization_tokens_ocaml_json::<mina_curves::pasta::Fq>(false)
}
