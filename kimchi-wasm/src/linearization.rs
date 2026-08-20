//! The linearization token streams for the `fp/fq_linearization_tokens`
//! OCaml externals. The tokens cross the wasm boundary as one JSON string in
//! the js_of_ocaml encoding produced by [`kimchi::linearization_tokens`]; the
//! JS side (`kimchi_bindings/js/bindings/linearization.js`) decodes it.

use kimchi::linearization_tokens::linearization_tokens_ocaml_json;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn fp_linearization_tokens() -> String {
    linearization_tokens_ocaml_json::<mina_curves::pasta::Fp>(true)
}

#[wasm_bindgen]
pub fn fq_linearization_tokens() -> String {
    linearization_tokens_ocaml_json::<mina_curves::pasta::Fq>(false)
}
