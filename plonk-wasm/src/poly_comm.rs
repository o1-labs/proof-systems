use crate::wasm_vector::WasmVector;
use paste::paste;
macro_rules! impl_poly_comm {
    (
     $WasmG: ty,
     $G: ty,
     $field_name: ident
     ) => {
        paste! {
            use wasm_bindgen::prelude::*;
            use poly_commitment::commitment::PolyComm;

            #[wasm_bindgen]
            #[derive(Clone)]
            pub struct [<Wasm $field_name:camel PolyComm>] {
                #[wasm_bindgen(skip)]
                pub unshifted: WasmVector<$WasmG>,
                pub shifted: Option<$WasmG>,
                #[wasm_bindgen(skip)]
                pub id: u64,
            }
            
            impl Drop for [<Wasm $field_name:camel PolyComm>] {
                fn drop(&mut self) {
                    let mut size = std::mem::size_of::<Self>();
                    // WasmVector size is already tracked separately
                    // Just add the shifted element size if present
                    if self.shifted.is_some() {
                        size += std::mem::size_of::<$WasmG>();
                    }
                    crate::memory_tracker::log_deallocation(concat!("Wasm", stringify!($field_name), "PolyComm"), size, self.id);
                }
            }

            type WasmPolyComm = [<Wasm $field_name:camel PolyComm>];

            #[wasm_bindgen]
            impl [<Wasm $field_name:camel PolyComm>] {
                #[wasm_bindgen(constructor)]
                pub fn new(unshifted: WasmVector<$WasmG>, shifted: Option<$WasmG>) -> Self {
                    assert!(
                        shifted.is_none(),
                        "mina#14628: Shifted commitments are deprecated and must not be used"
                    );
                    let id = crate::memory_tracker::next_id();
                    let mut size = std::mem::size_of::<WasmPolyComm>();
                    if shifted.is_some() {
                        size += std::mem::size_of::<$WasmG>();
                    }
                    crate::memory_tracker::log_allocation(concat!("Wasm", stringify!($field_name), "PolyComm"), size, file!(), line!(), id);
                    WasmPolyComm { unshifted, shifted, id }
                }

                #[wasm_bindgen(getter)]
                pub fn unshifted(&self) -> WasmVector<$WasmG> {
                    self.unshifted.clone()
                }

                #[wasm_bindgen(setter)]
                pub fn set_unshifted(&mut self, x: WasmVector<$WasmG>) {
                    self.unshifted = x
                }
            }

            impl From<PolyComm<$G>> for WasmPolyComm {
                fn from(x: PolyComm<$G>) -> Self {
                    let PolyComm { chunks } = x;
                    let unshifted: Vec<$WasmG> =
                        chunks.into_iter().map(|x| x.into()).collect();
                    let id = crate::memory_tracker::next_id();
                    let size = std::mem::size_of::<WasmPolyComm>();
                    crate::memory_tracker::log_allocation(concat!("Wasm", stringify!($field_name), "PolyComm"), size, file!(), line!(), id);
                    WasmPolyComm {
                        unshifted: unshifted.into(),
                        shifted: None,
                        id,
                    }
                }
            }

            impl From<&PolyComm<$G>> for WasmPolyComm {
                fn from(x: &PolyComm<$G>) -> Self {
                    let unshifted: Vec<$WasmG> =
                        x.chunks.iter().map(|x| x.into()).collect();
                    let id = crate::memory_tracker::next_id();
                    let size = std::mem::size_of::<WasmPolyComm>();
                    crate::memory_tracker::log_allocation(concat!("Wasm", stringify!($field_name), "PolyComm"), size, file!(), line!(), id);
                    WasmPolyComm {
                        unshifted: unshifted.into(),
                        shifted: None,
                        id,
                    }
                }
            }

            impl From<WasmPolyComm> for PolyComm<$G> {
                fn from(x: WasmPolyComm) -> Self {
                    assert!(
                        x.shifted.is_none(),
                        "mina#14628: Shifted commitments are deprecated and must not be used"
                    );
                    PolyComm {
                        chunks: x.unshifted.iter().map(|x| { (*x).into() }).collect(),
                    }
                }
            }

            impl From<&WasmPolyComm> for PolyComm<$G> {
                fn from(x: &WasmPolyComm) -> Self {
                    assert!(
                        x.shifted.is_none(),
                        "mina#14628: Shifted commitments are deprecated and must not be used"
                    );
                    PolyComm {
                        chunks: x.unshifted.iter().map(|x| { (*x).into() }).collect(),
                    }
                }
            }
        }
    };
}

pub mod pallas {
    use super::*;
    use arkworks::WasmGPallas;
    use mina_curves::pasta::Pallas as GAffine;

    impl_poly_comm!(WasmGPallas, GAffine, Fq);
}

pub mod vesta {
    use super::*;
    use arkworks::WasmGVesta;
    use mina_curves::pasta::Vesta as GAffine;

    impl_poly_comm!(WasmGVesta, GAffine, Fp);
}
