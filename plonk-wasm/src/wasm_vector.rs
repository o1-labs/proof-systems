use core::{convert::From, ops::Deref};
use paste::paste;
use wasm_bindgen::{
    convert::{FromWasmAbi, IntoWasmAbi, OptionFromWasmAbi, OptionIntoWasmAbi},
    prelude::*,
};
use wasm_types::FlatVector as WasmFlatVector;
use crate::memory_tracker::{next_id, log_allocation, log_deallocation, estimate_vec_size};

#[derive(Clone, Debug)]
pub struct WasmVector<T> {
    pub data: Vec<T>,
    pub id: u64,
}

impl<T> Deref for WasmVector<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T> WasmVector<T> {
    pub fn get(&self, index: usize) -> Option<&T> {
        self.data.get(index)
    }
}

impl<T> Drop for WasmVector<T> {
    fn drop(&mut self) {
        let size = estimate_vec_size(&self.data);
        log_deallocation("WasmVector", size, self.id);
    }
}

impl<T> From<Vec<T>> for WasmVector<T> {
    fn from(x: Vec<T>) -> Self {
        let id = next_id();
        let size = estimate_vec_size(&x);
        log_allocation("WasmVector", size, file!(), line!(), id);
        WasmVector { data: x, id }
    }
}

impl<T: Clone> From<WasmVector<T>> for Vec<T> {
    fn from(x: WasmVector<T>) -> Self {
        x.data.clone()
    }
}

impl<'a, T> From<&'a WasmVector<T>> for &'a Vec<T> {
    fn from(x: &'a WasmVector<T>) -> Self {
        &x.data
    }
}

impl<T: Clone> core::iter::IntoIterator for WasmVector<T> {
    type Item = <Vec<T> as core::iter::IntoIterator>::Item;
    type IntoIter = <Vec<T> as core::iter::IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.data.clone().into_iter()
    }
}

impl<'a, T> core::iter::IntoIterator for &'a WasmVector<T> {
    type Item = <&'a Vec<T> as core::iter::IntoIterator>::Item;
    type IntoIter = <&'a Vec<T> as core::iter::IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.data.iter()
    }
}

impl<T> core::iter::FromIterator<T> for WasmVector<T> {
    fn from_iter<I>(iter: I) -> WasmVector<T>
    where
        I: IntoIterator<Item = T>,
    {
        let data: Vec<T> = core::iter::FromIterator::from_iter(iter);
        let id = next_id();
        let size = estimate_vec_size(&data);
        log_allocation("WasmVector", size, file!(), line!(), id);
        WasmVector { data, id }
    }
}

impl<T> core::default::Default for WasmVector<T> {
    fn default() -> Self {
        let data = Vec::new();
        let id = next_id();
        let size = estimate_vec_size(&data);
        log_allocation("WasmVector", size, file!(), line!(), id);
        WasmVector { data, id }
    }
}

impl<T> core::iter::Extend<T> for WasmVector<T> {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = T>,
    {
        self.data.extend(iter)
    }
}

impl<T> wasm_bindgen::describe::WasmDescribe for WasmVector<T> {
    fn describe() {
        <Vec<u32> as wasm_bindgen::describe::WasmDescribe>::describe()
    }
}

impl<T: FromWasmAbi<Abi = u32>> FromWasmAbi for WasmVector<T> {
    type Abi = <Vec<u32> as FromWasmAbi>::Abi;
    unsafe fn from_abi(js: Self::Abi) -> Self {
        let pointers: Vec<u32> = FromWasmAbi::from_abi(js);
        let data: Vec<T> = pointers
            .into_iter()
            .map(|x| FromWasmAbi::from_abi(x))
            .collect();
        let id = next_id();
        let size = estimate_vec_size(&data);
        log_allocation("WasmVector", size, file!(), line!(), id);
        WasmVector { data, id }
    }
}

impl<T: FromWasmAbi<Abi = u32>> OptionFromWasmAbi for WasmVector<T> {
    fn is_none(x: &Self::Abi) -> bool {
        <Vec<u32> as OptionFromWasmAbi>::is_none(x)
    }
}

impl<T: IntoWasmAbi<Abi = u32> + Clone> IntoWasmAbi for WasmVector<T> {
    type Abi = <Vec<u32> as FromWasmAbi>::Abi;
    fn into_abi(self) -> Self::Abi {
        let pointers: Vec<u32> = self
            .data
            .clone()
            .into_iter()
            .map(|x| IntoWasmAbi::into_abi(x))
            .collect();
        IntoWasmAbi::into_abi(pointers)
    }
}

impl<T: IntoWasmAbi<Abi = u32> + Clone> OptionIntoWasmAbi for WasmVector<T> {
    fn none() -> Self::Abi {
        <Vec<u32> as OptionIntoWasmAbi>::none()
    }
}

macro_rules! impl_vec_vec_fp {
    ( $F:ty, $WasmF:ty ) => {
        paste! {
            #[wasm_bindgen]
            #[derive(Clone)]
            pub struct [<WasmVecVec $F:camel>] {
                #[wasm_bindgen(skip)] 
                pub data: Vec<Vec<$F>>,
                #[wasm_bindgen(skip)]
                pub id: u64,
            }

            #[wasm_bindgen]
            impl [<WasmVecVec $F:camel>] {
                #[wasm_bindgen(constructor)]
                pub fn create(n: i32) -> Self {
                    let data = Vec::with_capacity(n as usize);
                    let id = next_id();
                    let size = crate::memory_tracker::estimate_nested_vec_size(&data);
                    log_allocation(concat!("WasmVecVec", stringify!($F)), size, file!(), line!(), id);
                    [<WasmVecVec $F:camel>] { data, id }
                }

                #[wasm_bindgen]
                pub fn push(&mut self, x: WasmFlatVector<$WasmF>) {
                    self.data.push(x.into_iter().map(Into::into).collect())
                }

                #[wasm_bindgen]
                pub fn get(&self, i: i32) -> WasmFlatVector<$WasmF> {
                    self.data[i as usize].clone().into_iter().map(Into::into).collect()
                }

                #[wasm_bindgen]
                pub fn set(&mut self, i: i32, x: WasmFlatVector<$WasmF>) {
                    self.data[i as usize] = x.into_iter().map(Into::into).collect()
                }
            }

            impl Drop for [<WasmVecVec $F:camel>] {
                fn drop(&mut self) {
                    let size = crate::memory_tracker::estimate_nested_vec_size(&self.data);
                    log_deallocation(concat!("WasmVecVec", stringify!($F)), size, self.id);
                }
            }
        }
    };
}

pub mod fp {
    use super::*;
    use arkworks::WasmPastaFp;
    use mina_curves::pasta::Fp;

    impl_vec_vec_fp!(Fp, WasmPastaFp);
}

pub mod fq {
    use super::*;
    use arkworks::WasmPastaFq;
    use mina_curves::pasta::Fq;

    impl_vec_vec_fp!(Fq, WasmPastaFq);
}
