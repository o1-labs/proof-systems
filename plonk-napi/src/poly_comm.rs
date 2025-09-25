use crate::{
    wasm_vector::WasmVector,
    wrappers::group::{WasmGPallas, WasmGVesta},
};
use napi_derive::napi;
use paste::paste;
use poly_commitment::PolyComm;

macro_rules! impl_poly_comm {
    (
        $wasm_g:ty,
        $g:ty,
        $field_name:ident
    ) => {
        paste! {
            #[napi]
            #[derive(Clone)]
            pub struct [<Wasm $field_name:camel PolyComm>] {
                #[napi(skip)]
                pub unshifted: WasmVector<$wasm_g>,
                pub shifted: Option<$wasm_g>,
            }

            #[napi]
            impl [<Wasm $field_name:camel PolyComm>] {
                #[napi(constructor)]
                pub fn new(unshifted: WasmVector<$wasm_g>, shifted: Option<$wasm_g>) -> Self {
                    assert!(
                        shifted.is_none(),
                        "mina#14628: Shifted commitments are deprecated and must not be used",
                    );
                    Self { unshifted, shifted }
                }

                #[napi(getter)]
                pub fn unshifted(&self) -> WasmVector<$wasm_g> {
                    self.unshifted.clone()
                }

                #[napi(setter)]
                pub fn set_unshifted(&mut self, value: WasmVector<$wasm_g>) {
                    self.unshifted = value;
                }
            }

            impl From<PolyComm<$g>> for [<Wasm $field_name:camel PolyComm>] {
                fn from(value: PolyComm<$g>) -> Self {
                    let PolyComm { chunks } = value;
                    let unshifted: Vec<$wasm_g> = chunks.into_iter().map(Into::into).collect();
                    Self {
                        unshifted: unshifted.into(),
                        shifted: None,
                    }
                }
            }

            impl From<&PolyComm<$g>> for [<Wasm $field_name:camel PolyComm>] {
                fn from(value: &PolyComm<$g>) -> Self {
                    let unshifted: Vec<$wasm_g> = value.chunks.iter().map(|chunk| (*chunk).into()).collect();
                    Self {
                        unshifted: unshifted.into(),
                        shifted: None,
                    }
                }
            }

            impl From<[<Wasm $field_name:camel PolyComm>]> for PolyComm<$g> {
                fn from(value: [<Wasm $field_name:camel PolyComm>]) -> Self {
                    let [<Wasm $field_name:camel PolyComm>] { unshifted, shifted } = value;
                    assert!(
                        shifted.is_none(),
                        "mina#14628: Shifted commitments are deprecated and must not be used",
                    );
                    PolyComm {
                        chunks: Vec::<$wasm_g>::from(unshifted)
                            .into_iter()
                            .map(Into::into)
                            .collect(),
                    }
                }
            }

            impl From<&[<Wasm $field_name:camel PolyComm>]> for PolyComm<$g> {
                fn from(value: &[<Wasm $field_name:camel PolyComm>]) -> Self {
                    assert!(
                        value.shifted.is_none(),
                        "mina#14628: Shifted commitments are deprecated and must not be used",
                    );
                    PolyComm {
                        chunks: value
                            .unshifted
                            .iter()
                            .cloned()
                            .map(Into::into)
                            .collect(),
                    }
                }
            }
        }
    };
}

pub mod pallas {
    use super::*;
    use mina_curves::pasta::Pallas as GAffine;

    impl_poly_comm!(WasmGPallas, GAffine, Fq);
}

pub mod vesta {
    use super::*;
    use mina_curves::pasta::Vesta as GAffine;

    impl_poly_comm!(WasmGVesta, GAffine, Fp);
}
