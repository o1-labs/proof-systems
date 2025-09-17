use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::handles::{GlobalHandleStore, Handle};

#[derive(Clone, Debug)]
struct StoredPolyComm {
    unshifted: Vec<Handle>,
    #[allow(dead_code)]
    shifted: Option<Handle>,
}

fn handles_from_uint32array(array: &Uint32Array) -> Vec<Handle> {
    array
        .to_vec()
        .into_iter()
        .map(|value| value as Handle)
        .collect()
}

macro_rules! impl_poly_comm {
    ($store:ident, $struct_name:ident) => {
        static $store: GlobalHandleStore<StoredPolyComm> = GlobalHandleStore::new();

        #[napi]
        pub struct $struct_name {
            handle: Handle,
        }

        #[napi]
        impl $struct_name {
            #[napi(constructor)]
            pub fn new(unshifted: Uint32Array, shifted: Option<Uint32Array>) -> Result<Self> {
                if shifted.is_some() {
                    return Err(Error::new(
                        Status::InvalidArg,
                        "mina#14628: Shifted commitments are deprecated and must not be used",
                    ));
                }

                let handles = handles_from_uint32array(&unshifted);
                let stored = StoredPolyComm {
                    unshifted: handles,
                    shifted: None,
                };

                let handle = $store.lock().insert(stored);
                Ok(Self { handle })
            }

            #[napi(getter)]
            pub fn unshifted(&self) -> Result<Uint32Array> {
                let stored = {
                    let guard = $store.lock();
                    guard.get(self.handle).cloned().ok_or_else(|| {
                        Error::new(Status::InvalidArg, "unknown poly commitment handle")
                    })?
                };
                Ok(Uint32Array::new(stored.unshifted.clone()))
            }

            #[napi(setter)]
            pub fn set_unshifted(&mut self, value: Uint32Array) -> Result<()> {
                let handles = handles_from_uint32array(&value);
                let mut guard = $store.lock();
                match guard.get_mut(self.handle) {
                    Some(entry) => {
                        entry.unshifted = handles;
                        Ok(())
                    }
                    None => Err(Error::new(
                        Status::InvalidArg,
                        "unknown poly commitment handle",
                    )),
                }
            }

            #[napi]
            pub fn free(&mut self) {
                let _ = $store.lock().remove(self.handle);
                self.handle = 0;
            }
        }
    };
}

pub mod pallas {
    use super::*;
    impl_poly_comm!(FP_POLY_COMM_STORE, WasmFqPolyComm);
}

pub mod vesta {
    use super::*;
    impl_poly_comm!(FQ_POLY_COMM_STORE, WasmFpPolyComm);
}
