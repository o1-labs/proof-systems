//! Neon counterparts of the wasm `WasmFpPolyComm` / `WasmFqPolyComm` classes.
//!
//! This file sketches the API surface required to emulate the wasm_bindgen
//! layer. The actual point/vector infrastructure will be supplied in later
//! steps; for now the implementations operate purely on opaque handles.

use neon::prelude::*;

use crate::handles::{handles_from_js_array, handles_to_js_array, GlobalHandleStore, Handle};

#[derive(Clone, Debug)]
struct StoredPolyComm {
    unshifted: Vec<Handle>, // replace with WasmG
    shifted: Option<Handle>,
}

macro_rules! impl_poly_comm {
    ($store:ident, $class:ident) => {
        static $store: GlobalHandleStore<StoredPolyComm> = GlobalHandleStore::new();

        #[neon::class]
        pub struct $class {
            handle: Handle,
        }

        #[neon::class]
        impl $class {
            fn new(mut cx: FunctionContext) -> JsResult<Self> {
                let unshifted: Handle<JsArray> = cx.argument(0)?;
                let shifted = cx.argument_opt(1);

                if let Some(value) = shifted {
                    if !value.is_a::<JsUndefined, _>(&mut cx) {
                        return cx.throw_error(
                            "mina#14628: Shifted commitments are deprecated and must not be used",
                        );
                    }
                }

                let handles = handles_from_js_array(&mut cx, unshifted)?;
                let stored = StoredPolyComm {
                    unshifted: handles,
                    shifted: None,
                };

                let handle = $store.lock().insert(stored);
                Ok(Self { handle })
            }

            fn unshifted(&self, mut cx: FunctionContext) -> JsResult<JsArray> {
                let stored = {
                    let store = $store.lock();
                    match store.get(self.handle) {
                        Some(value) => value.clone(),
                        None => return cx.throw_error("unknown PolyComm handle"),
                    }
                };
                handles_to_js_array(&mut cx, &stored.unshifted)
            }

            fn set_unshifted(
                &mut self,
                mut cx: FunctionContext,
                value: Handle<JsArray>,
            ) -> JsResult<()> {
                let handles = handles_from_js_array(&mut cx, value)?;
                let mut store = $store.lock();
                match store.get_mut(self.handle) {
                    Some(entry) => {
                        entry.unshifted = handles;
                        Ok(())
                    }
                    None => cx.throw_error("unknown PolyComm handle"),
                }
            }

            fn free(mut self, mut cx: FunctionContext) -> JsResult<JsUndefined> {
                let _ = $store.lock().remove(self.handle);
                self.handle = 0;
                Ok(cx.undefined())
            }
        }

        impl Finalize for $class {}
    };
}

pub mod pallas {
    impl_poly_comm!(FQ_POLY_COMM_STORE, WasmFqPolyComm);
}

pub mod vesta {
    impl_poly_comm!(FP_POLY_COMM_STORE, WasmFpPolyComm);
}
