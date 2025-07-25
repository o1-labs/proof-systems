use core::{convert::From, ops::Deref};
use paste::paste;
use wasm_bindgen::{
    convert::{FromWasmAbi, IntoWasmAbi, OptionFromWasmAbi, OptionIntoWasmAbi},
    prelude::*,
};
use wasm_types::FlatVector as WasmFlatVector;

#[derive(Clone, Debug)]
pub struct WasmVector<T>(Vec<T>);

impl<T> Deref for WasmVector<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> From<Vec<T>> for WasmVector<T> {
    fn from(x: Vec<T>) -> Self {
        WasmVector(x)
    }
}

impl<T> From<WasmVector<T>> for Vec<T> {
    fn from(x: WasmVector<T>) -> Self {
        x.0
    }
}

impl<'a, T> From<&'a WasmVector<T>> for &'a Vec<T> {
    fn from(x: &'a WasmVector<T>) -> Self {
        &x.0
    }
}

impl<T> core::iter::IntoIterator for WasmVector<T> {
    type Item = <Vec<T> as core::iter::IntoIterator>::Item;
    type IntoIter = <Vec<T> as core::iter::IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T> core::iter::IntoIterator for &'a WasmVector<T> {
    type Item = <&'a Vec<T> as core::iter::IntoIterator>::Item;
    type IntoIter = <&'a Vec<T> as core::iter::IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T> core::iter::FromIterator<T> for WasmVector<T> {
    fn from_iter<I>(iter: I) -> WasmVector<T>
    where
        I: IntoIterator<Item = T>,
    {
        WasmVector(core::iter::FromIterator::from_iter(iter))
    }
}

impl<T> core::default::Default for WasmVector<T> {
    fn default() -> Self {
        WasmVector(core::default::Default::default())
    }
}

impl<T> core::iter::Extend<T> for WasmVector<T> {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = T>,
    {
        self.0.extend(iter)
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
        WasmVector(
            pointers
                .into_iter()
                .map(|x| FromWasmAbi::from_abi(x))
                .collect(),
        )
    }
}

impl<T: FromWasmAbi<Abi = u32>> OptionFromWasmAbi for WasmVector<T> {
    fn is_none(x: &Self::Abi) -> bool {
        <Vec<u32> as OptionFromWasmAbi>::is_none(x)
    }
}

impl<T: IntoWasmAbi<Abi = u32>> IntoWasmAbi for WasmVector<T> {
    type Abi = <Vec<u32> as FromWasmAbi>::Abi;
    fn into_abi(self) -> Self::Abi {
        let pointers: Vec<u32> = self
            .0
            .into_iter()
            .map(|x| IntoWasmAbi::into_abi(x))
            .collect();
        IntoWasmAbi::into_abi(pointers)
    }
}

impl<T: IntoWasmAbi<Abi = u32>> OptionIntoWasmAbi for WasmVector<T> {
    fn none() -> Self::Abi {
        <Vec<u32> as OptionIntoWasmAbi>::none()
    }
}

macro_rules! impl_vec_vec_fp {
    ( $F:ty, $WasmF:ty ) => {
        paste! {
            #[wasm_bindgen]
            pub struct [<WasmVecVec $F:camel>](#[wasm_bindgen(skip)] pub Vec<Vec<$F>>);

            #[wasm_bindgen]
            impl [<WasmVecVec $F:camel>] {
                #[wasm_bindgen(constructor)]
                pub fn create(n: i32) -> Self {
                    [<WasmVecVec $F:camel>](Vec::with_capacity(n as usize))
                }

                #[wasm_bindgen]
                pub fn push(&mut self, x: WasmFlatVector<$WasmF>) {
                    self.0.push(x.into_iter().map(Into::into).collect())
                }

                #[wasm_bindgen]
                pub fn get(&self, i: i32) -> WasmFlatVector<$WasmF> {
                    self.0[i as usize].clone().into_iter().map(Into::into).collect()
                }

                #[wasm_bindgen]
                pub fn set(&mut self, i: i32, x: WasmFlatVector<$WasmF>) {
                    self.0[i as usize] = x.into_iter().map(Into::into).collect()
                }
            }
        }
    };
}

macro_rules! impl_vec_fp {
    ( $F:ty, $WasmF:ty ) => {
        paste! {
            #[wasm_bindgen]
            pub struct [<WasmVec $F:camel>](#[wasm_bindgen(skip)] pub Vec<$F>);

            #[wasm_bindgen]
            impl [<WasmVec $F:camel>] {
                #[wasm_bindgen(constructor)]
                pub fn create(n: i32) -> Self {
                    [<WasmVec $F:camel>](Vec::with_capacity(n as usize))
                }

                #[wasm_bindgen]
                pub fn push(&mut self, x: $WasmF) {
                    self.0.push(Into::into(x))
                }

                #[wasm_bindgen]
                pub fn get(&self, i: i32) -> $WasmF {
                    Into::into(self.0[i as usize].clone())
                }

                #[wasm_bindgen]
                pub fn set(&mut self, i: i32, x: $WasmF) {
                    self.0[i as usize] = Into::into(x)
                }
            }
        }
    };
}

pub mod fp {
    use super::*;
    use arkworks::WasmPastaFp;
    use mina_curves::pasta::Fp;

    impl_vec_fp!(Fp, WasmPastaFp);
    impl_vec_vec_fp!(Fp, WasmPastaFp);
}

pub mod fq {
    use super::*;
    use arkworks::WasmPastaFq;
    use mina_curves::pasta::Fq;

    impl_vec_fp!(Fq, WasmPastaFq);
    impl_vec_vec_fp!(Fq, WasmPastaFq);
}
