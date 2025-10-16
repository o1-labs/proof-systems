use crate::wasm_vector::WasmVector;
use napi_derive::napi;
use paste::paste;
use poly_commitment::commitment::PolyComm;

macro_rules! impl_poly_comm {
    (
        $WasmG:ty,
        $g:ty,
        $field_name:ident
    ) => {
        paste! {
            #[napi]
            #[derive(Clone)]
            pub struct [<Wasm $field_name:camel PolyComm>] {
                #[napi(skip)]
                pub unshifted: WasmVector<$WasmG>,
                pub shifted: Option<$WasmG>,
            }

            #[napi]
            impl [<Wasm $field_name:camel PolyComm>] {
                #[napi(constructor)]
                pub fn new(unshifted: WasmVector<$WasmG>, shifted: Option<$WasmG>) -> Self {
                    assert!(
                        shifted.is_none(),
                        "mina#14628: Shifted commitments are deprecated and must not be used",
                    );
                    Self { unshifted, shifted }
                }

                #[napi(getter)]
                pub fn unshifted(&self) -> WasmVector<$WasmG> {
                    self.unshifted.clone()
                }

                #[napi(setter)]
                pub fn set_unshifted(&mut self, x: WasmVector<$WasmG>) {
                    self.unshifted = x;
                }
            }

            impl From<PolyComm<$g>> for [<Wasm $field_name:camel PolyComm>] {
                fn from(x: PolyComm<$g>) -> Self {
                    let PolyComm { chunks } = x;
                    let unshifted: Vec<$WasmG> = chunks.into_iter().map(Into::into).collect();
                    Self {
                        unshifted: unshifted.into(),
                        shifted: None,
                    }
                }
            }

            impl From<&PolyComm<$g>> for [<Wasm $field_name:camel PolyComm>] {
                fn from(x: &PolyComm<$g>) -> Self {
                    let unshifted: Vec<$WasmG> = x.chunks.iter().map(|chunk| (*chunk).into()).collect();
                    Self {
                        unshifted: unshifted.into(),
                        shifted: None,
                    }
                }
            }

            impl From<[<Wasm $field_name:camel PolyComm>]> for PolyComm<$g> {
                fn from(x: [<Wasm $field_name:camel PolyComm>]) -> Self {
                    let [<Wasm $field_name:camel PolyComm>] { unshifted, shifted } = x;
                    assert!(
                        shifted.is_none(),
                        "mina#14628: Shifted commitments are deprecated and must not be used",
                    );
                    PolyComm {
                        chunks: Vec::<$WasmG>::from(unshifted)
                            .into_iter()
                            .map(Into::into)
                            .collect(),
                    }
                }
            }

            impl From<&[<Wasm $field_name:camel PolyComm>]> for PolyComm<$g> {
                fn from(x: &[<Wasm $field_name:camel PolyComm>]) -> Self {
                    assert!(
                        x.shifted.is_none(),
                        "mina#14628: Shifted commitments are deprecated and must not be used",
                    );
                    PolyComm {
                        chunks: x
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
    use crate::wrappers::group::WasmGPallas;
    use mina_curves::pasta::Pallas as GAffine;

    impl_poly_comm!(WasmGPallas, GAffine, Fq);
}

pub mod vesta {
    use super::*;
    use crate::wrappers::group::WasmGVesta;
    use mina_curves::pasta::Vesta as GAffine;

    impl_poly_comm!(WasmGVesta, GAffine, Fp);
}
