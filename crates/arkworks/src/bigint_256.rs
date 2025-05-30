extern crate alloc;

use alloc::{string::String, vec::Vec};
use ark_ff::{BigInt, BigInteger as ark_BigInteger, BigInteger256};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use core::{
    cmp::Ordering::{Equal, Greater, Less},
    convert::TryInto,
};
use num_bigint::BigUint;
use wasm_bindgen::{
    convert::{FromWasmAbi, IntoWasmAbi},
    prelude::*,
};

//
// Handy constants
//

const BIGINT256_NUM_BITS: i32 = 256;
const BIGINT256_LIMB_BITS: i32 = 64;
const BIGINT256_LIMB_BYTES: i32 = BIGINT256_LIMB_BITS / 8;
const BIGINT256_NUM_LIMBS: i32 =
    (BIGINT256_NUM_BITS + BIGINT256_LIMB_BITS - 1) / BIGINT256_LIMB_BITS;
const BIGINT256_NUM_BYTES: usize = (BIGINT256_NUM_LIMBS as usize) * 8;

pub struct WasmBigInteger256(pub BigInteger256);

impl wasm_bindgen::describe::WasmDescribe for WasmBigInteger256 {
    fn describe() {
        <Vec<u8> as wasm_bindgen::describe::WasmDescribe>::describe();
    }
}

impl FromWasmAbi for WasmBigInteger256 {
    type Abi = <Vec<u8> as FromWasmAbi>::Abi;
    unsafe fn from_abi(js: Self::Abi) -> Self {
        let bytes: Vec<u8> = FromWasmAbi::from_abi(js);
        // TODO this used FromBytes before arkworks 0.4.2, check serialization is consistent after update
        WasmBigInteger256(BigInteger256::deserialize_compressed(bytes.as_slice()).unwrap())
    }
}

impl IntoWasmAbi for WasmBigInteger256 {
    type Abi = <Vec<u8> as FromWasmAbi>::Abi;

    fn into_abi(self) -> Self::Abi {
        self.0.to_bytes_le().into_abi()
    }
}

pub fn to_biguint(x: &BigInteger256) -> BigUint {
    let x_ = x.0.as_ptr().cast::<u8>();
    let x_ = unsafe { core::slice::from_raw_parts(x_, BIGINT256_NUM_BYTES) };
    num_bigint::BigUint::from_bytes_le(x_)
}

pub fn of_biguint(x: &BigUint) -> BigInteger256 {
    let mut bytes = x.to_bytes_le();
    bytes.resize(BIGINT256_NUM_BYTES, 0);
    let limbs = bytes.as_ptr();
    let limbs = limbs.cast::<[u64; BIGINT256_NUM_LIMBS as usize]>();
    let limbs = unsafe { &(*limbs) };
    BigInt(*limbs)
}

#[wasm_bindgen]
pub fn caml_bigint_256_of_numeral(s: String, _len: u32, base: u32) -> WasmBigInteger256 {
    match BigUint::parse_bytes(&s.into_bytes(), base) {
        Some(data) => WasmBigInteger256(of_biguint(&data)),
        None => panic!("caml_bigint_256_of_numeral"),
    }
}

#[wasm_bindgen]
pub fn caml_bigint_256_of_decimal_string(s: String) -> WasmBigInteger256 {
    match BigUint::parse_bytes(&s.into_bytes(), 10) {
        Some(data) => WasmBigInteger256(of_biguint(&data)),
        None => panic!("caml_bigint_256_of_decimal_string"),
    }
}

#[wasm_bindgen]
pub fn caml_bigint_256_num_limbs() -> i32 {
    BIGINT256_NUM_LIMBS
}

#[wasm_bindgen]
pub fn caml_bigint_256_bytes_per_limb() -> i32 {
    BIGINT256_LIMB_BYTES
}

#[wasm_bindgen]
pub fn caml_bigint_256_div(x: WasmBigInteger256, y: WasmBigInteger256) -> WasmBigInteger256 {
    let res: BigUint = to_biguint(&x.0) / to_biguint(&y.0);
    WasmBigInteger256(of_biguint(&res))
}

#[wasm_bindgen]
pub fn caml_bigint_256_compare(x: WasmBigInteger256, y: WasmBigInteger256) -> i8 {
    match x.0.cmp(&y.0) {
        Less => -1,
        Equal => 0,
        Greater => 1,
    }
}

// I don't think this is used anywhere
#[cfg_attr(feature = "std", wasm_bindgen)]
#[cfg(feature = "std")]
pub fn caml_bigint_256_print(x: WasmBigInteger256) {
    println!("{}", to_biguint(&x.0));
}

// I don't think this is used anywhere
#[cfg_attr(feature = "std", wasm_bindgen)]
#[cfg(feature = "std")]
pub fn caml_bigint_256_to_string(x: WasmBigInteger256) -> String {
    to_biguint(&x.0).to_string()
}

#[wasm_bindgen]
pub fn caml_bigint_256_test_bit(x: WasmBigInteger256, i: i32) -> bool {
    match i.try_into() {
        Ok(i) => x.0.get_bit(i),
        Err(_) => panic!("caml_bigint_256_test_bit"),
    }
}

#[wasm_bindgen]
pub fn caml_bigint_256_to_bytes(x: WasmBigInteger256) -> Vec<u8> {
    // This is the size of the implementation of BigInteger256 at the time of writing
    // but even if it changes, we will be no worse off than the original code `vec![]`
    let mut serialized_bytes = Vec::with_capacity(core::mem::size_of::<WasmBigInteger256>());
    x.0.serialize_compressed(&mut serialized_bytes)
        .expect("serialize failed");
    serialized_bytes
}

#[wasm_bindgen]
pub fn caml_bigint_256_of_bytes(x: &[u8]) -> WasmBigInteger256 {
    let len = core::mem::size_of::<WasmBigInteger256>();
    assert!(x.len() == len, "caml_bigint_256_of_bytes");
    // TODO this used FromBytes before arkworks 0.4.2, check serialization is consistent after update
    WasmBigInteger256(
        BigInteger256::deserialize_compressed(&mut &x[..]).expect("deserialization error"),
    )
}

#[wasm_bindgen]
pub fn caml_bigint_256_deep_copy(x: WasmBigInteger256) -> WasmBigInteger256 {
    x
}
