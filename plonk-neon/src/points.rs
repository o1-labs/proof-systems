use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mina_curves::pasta::{Pallas as AffinePallas, Vesta as AffineVesta, Fp, Fq};
use neon::{prelude::*, types::buffer::TypedArray};

use crate::handles::{GlobalHandleStore, Handle};

fn serialize_field<F: CanonicalSerialize>(field: &F) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(field.compressed_size());
    field
        .serialize_compressed(&mut bytes)
        .expect("field serialization should succeed");
    bytes
}

fn deserialize_fp(bytes: &[u8]) -> Result<Fp, String> {
    Fp::deserialize_compressed(bytes).map_err(|_| "invalid Fp encoding".to_string())
}

fn deserialize_fq(bytes: &[u8]) -> Result<Fq, String> {
    Fq::deserialize_compressed(bytes).map_err(|_| "invalid Fq encoding".to_string())
}

static VESTA_AFFINE_STORE: GlobalHandleStore<AffineVesta> = GlobalHandleStore::new();
static PALLAS_AFFINE_STORE: GlobalHandleStore<AffinePallas> = GlobalHandleStore::new();

fn store_vesta(point: AffineVesta) -> Handle {
    VESTA_AFFINE_STORE.lock().insert(point)
}

fn store_pallas(point: AffinePallas) -> Handle {
    PALLAS_AFFINE_STORE.lock().insert(point)
}

fn get_vesta(handle: Handle) -> Option<AffineVesta> {
    VESTA_AFFINE_STORE.lock().get(handle).cloned()
}

fn get_pallas(handle: Handle) -> Option<AffinePallas> {
    PALLAS_AFFINE_STORE.lock().get(handle).cloned()
}

fn update_vesta<F>(handle: Handle, mut f: F) -> Result<(), String>
where
    F: FnMut(&mut AffineVesta),
{
    let mut guard = VESTA_AFFINE_STORE.lock();
    match guard.get_mut(handle) {
        Some(point) => {
            f(point);
            Ok(())
        }
        None => Err("unknown Vesta affine handle".to_string()),
    }
}

fn update_pallas<F>(handle: Handle, mut f: F) -> Result<(), String>
where
    F: FnMut(&mut AffinePallas),
{
    let mut guard = PALLAS_AFFINE_STORE.lock();
    match guard.get_mut(handle) {
        Some(point) => {
            f(point);
            Ok(())
        }
        None => Err("unknown Pallas affine handle".to_string()),
    }
}

fn remove_vesta(handle: Handle) {
    let _ = VESTA_AFFINE_STORE.lock().remove(handle);
}

fn remove_pallas(handle: Handle) {
    let _ = PALLAS_AFFINE_STORE.lock().remove(handle);
}

macro_rules! impl_affine_class {
    ($name:ident, $affine:ty, $store_get:ident, $store_update:ident, $store_remove:ident, $deserialize_field:ident) => {
        #[neon::class]
        pub struct $name {
            handle: Handle,
        }

        #[neon::class]
        impl $name {
            fn new(mut cx: FunctionContext) -> JsResult<Self> {
                let point = <$affine>::default();
                Ok(Self {
                    handle: $store_get(point),
                })
            }

            fn builder(mut builder: ClassBuilder<Self>) -> NeonResult<()> {
                builder.property("x", |mut cx, this| {
                    let handle = {
                        let guard = cx.lock();
                        let this = this.borrow(&guard);
                        this.handle
                    };
                    let point = get_point(handle)?;
                    let bytes = serialize_field(&point.x);
                    let array = JsUint8Array::new(&mut cx, bytes.len() as u32)?;
                    array.as_mut_slice(&mut cx).copy_from_slice(&bytes);
                    Ok(array)
                }, |mut cx, this, value: Handle<JsValue>| {
                    let array = value.downcast_or_throw::<JsUint8Array, _>(&mut cx)?;
                    let data = array.as_slice(&cx).to_vec();
                    let field = $deserialize_field(&data).map_err(|err| cx.throw_error(err))?;
                    let handle = {
                        let guard = cx.lock();
                        let this = this.borrow(&guard);
                        this.handle
                    };
                    $store_update(handle, |point| point.x = field).map_err(|err| cx.throw_error(err))?;
                    Ok(())
                })?;

                builder.property("y", |mut cx, this| {
                    let handle = {
                        let guard = cx.lock();
                        let this = this.borrow(&guard);
                        this.handle
                    };
                    let point = get_point(handle)?;
                    let bytes = serialize_field(&point.y);
                    let array = JsUint8Array::new(&mut cx, bytes.len() as u32)?;
                    array.as_mut_slice(&mut cx).copy_from_slice(&bytes);
                    Ok(array)
                }, |mut cx, this, value: Handle<JsValue>| {
                    let array = value.downcast_or_throw::<JsUint8Array, _>(&mut cx)?;
                    let data = array.as_slice(&cx).to_vec();
                    let field = $deserialize_field(&data).map_err(|err| cx.throw_error(err))?;
                    let handle = {
                        let guard = cx.lock();
                        let this = this.borrow(&guard);
                        this.handle
                    };
                    $store_update(handle, |point| point.y = field).map_err(|err| cx.throw_error(err))?;
                    Ok(())
                })?;

                builder.property("infinity", |mut cx, this| {
                    let handle = {
                        let guard = cx.lock();
                        let this = this.borrow(&guard);
                        this.handle
                    };
                    let point = get_point(handle)?;
                    Ok(cx.boolean(point.infinity))
                }, |mut cx, this, value: Handle<JsValue>| {
                    let infinity = value.downcast_or_throw::<JsBoolean, _>(&mut cx)?.value(&mut cx);
                    let handle = {
                        let guard = cx.lock();
                        let this = this.borrow(&guard);
                        this.handle
                    };
                    $store_update(handle, |point| point.infinity = infinity).map_err(|err| cx.throw_error(err))?;
                    Ok(())
                })?;

                builder.method("free", |mut cx, this, _args: Vec<Handle<JsValue>>| {
                    let handle = {
                        let mut guard = cx.lock();
                        let mut this = this.borrow_mut(&mut guard);
                        let handle = this.handle;
                        this.handle = 0;
                        handle
                    };
                    $store_remove(handle);
                    Ok(cx.undefined())
                })?;

                Ok(())
            }
        }

        impl Finalize for $name {}

        fn get_point(handle: Handle) -> Result<$affine, neon::result::Throw> {
            get_fn(handle).ok_or_else(|| neon::result::Throw)
        }

        fn get_fn(handle: Handle) -> Option<$affine> {
            $store_get(handle)
        }
    };
}

impl_affine_class!(WasmGVesta, AffineVesta, store_vesta, update_vesta, remove_vesta, deserialize_fp);
impl_affine_class!(WasmGPallas, AffinePallas, store_pallas, update_pallas, remove_pallas, deserialize_fq);
