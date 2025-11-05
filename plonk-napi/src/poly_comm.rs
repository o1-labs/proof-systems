use crate::vector::NapiVector;
use napi::bindgen_prelude::{ClassInstance, FromNapiValue};
use napi_derive::napi;
use paste::paste;
use poly_commitment::commitment::PolyComm;
use serde::{Deserialize, Serialize};

macro_rules! impl_poly_comm {
    (
        $NapiG:ty,
        $g:ty,
        $field_name:ident
    ) => {
        paste! {
            #[napi(js_name = [<"Wasm" $field_name "PolyComm">])]
            #[derive(Clone, Debug, Serialize, Deserialize, Default)]
            pub struct [<Napi $field_name:camel PolyComm>] {
                #[napi(skip)]
                pub unshifted: NapiVector<$NapiG>,
                #[napi(skip)]
                pub shifted: Option<$NapiG>,
            }

            #[napi]
            impl [<Napi $field_name:camel PolyComm>] {
                #[napi(constructor)]
                pub fn new(unshifted: NapiVector<$NapiG>, shifted: Option<$NapiG>) -> Self {
                    assert!(
                        shifted.is_none(),
                        "mina#14628: Shifted commitments are deprecated and must not be used",
                    );
                    Self { unshifted, shifted }
                }

                #[napi(getter)]
                pub fn unshifted(&self) -> NapiVector<$NapiG> {
                    self.unshifted.clone()
                }

                #[napi(setter, js_name = "set_unshifted")]
                pub fn set_unshifted(&mut self, x: NapiVector<$NapiG>) {
                    self.unshifted = x;
                }

                #[napi(getter)]
                pub fn shifted(&self) -> Option<$NapiG> {
                    self.shifted.clone()
                }

                #[napi(setter, js_name = "set_shifted")]
                pub fn set_shifted(&mut self, value: Option<$NapiG>) {
                    self.shifted = value;
                }
            }

            impl From<PolyComm<$g>> for [<Napi $field_name:camel PolyComm>] {
                fn from(x: PolyComm<$g>) -> Self {
                    let PolyComm { chunks } = x;
                    let unshifted: Vec<$NapiG> = chunks.into_iter().map(Into::into).collect();
                    Self {
                        unshifted: unshifted.into(),
                        shifted: None,
                    }
                }
            }

            impl From<&PolyComm<$g>> for [<Napi $field_name:camel PolyComm>] {
                fn from(x: &PolyComm<$g>) -> Self {
                    let unshifted: Vec<$NapiG> = x.chunks.iter().map(|chunk| (*chunk).into()).collect();
                    Self {
                        unshifted: unshifted.into(),
                        shifted: None,
                    }
                }
            }

            impl From<[<Napi $field_name:camel PolyComm>]> for PolyComm<$g> {
                fn from(x: [<Napi $field_name:camel PolyComm>]) -> Self {
                    let [<Napi $field_name:camel PolyComm>] { unshifted, shifted } = x;
                    assert!(
                        shifted.is_none(),
                        "mina#14628: Shifted commitments are deprecated and must not be used",
                    );
                    PolyComm {
                        chunks: Vec::<$NapiG>::from(unshifted)
                            .into_iter()
                            .map(Into::into)
                            .collect(),
                    }
                }
            }

            impl From<&[<Napi $field_name:camel PolyComm>]> for PolyComm<$g> {
                fn from(x: &[<Napi $field_name:camel PolyComm>]) -> Self {
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

            impl FromNapiValue for [<Napi $field_name:camel PolyComm>] {
                unsafe fn from_napi_value(
                    env: napi::sys::napi_env,
                    napi_val: napi::sys::napi_value,
                ) -> napi::Result<Self> {
                    let instance = <ClassInstance<[<Napi $field_name:camel PolyComm>]> as FromNapiValue>::from_napi_value(env, napi_val)?;
                    Ok((*instance).clone())
                }
            }

        }
    };
}

pub mod pallas {
    use super::*;
    use crate::wrappers::group::NapiGPallas;
    use mina_curves::pasta::Pallas;

    impl_poly_comm!(NapiGPallas, Pallas, Fq);
}

pub mod vesta {
    use super::*;
    use crate::wrappers::group::NapiGVesta;
    use mina_curves::pasta::Vesta;

    impl_poly_comm!(NapiGVesta, Vesta, Fp);
}
