use crate::arkworks::bigint_256::{self, WasmBigInteger256};
use ark_ff::{
    fields::{Field, PrimeField},
    FftField, One, UniformRand, Zero,
};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as Domain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::cmp::Ordering::{Equal, Greater, Less};
use mina_curves::pasta::{
    fields::{fft::FpParameters, fq::FqParameters as Fq_params},
    Fq,
};
use num_bigint::BigUint;
use rand::rngs::StdRng;
use wasm_bindgen::{
    convert::{FromWasmAbi, IntoWasmAbi, OptionFromWasmAbi, OptionIntoWasmAbi},
    prelude::*,
};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WasmPastaFq(pub Fq);

impl crate::wasm_flat_vector::FlatVectorElem for WasmPastaFq {
    const FLATTENED_SIZE: usize = core::mem::size_of::<Fq>();
    fn flatten(self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(Self::FLATTENED_SIZE);
        self.0.serialize_compressed(&mut bytes).unwrap();
        bytes
    }
    fn unflatten(flat: Vec<u8>) -> Self {
        WasmPastaFq(Fq::deserialize_compressed(flat.as_slice()).unwrap())
    }
}

impl From<Fq> for WasmPastaFq {
    fn from(x: Fq) -> Self {
        WasmPastaFq(x)
    }
}

impl From<WasmPastaFq> for Fq {
    fn from(x: WasmPastaFq) -> Self {
        x.0
    }
}

impl<'a> From<&'a WasmPastaFq> for &'a Fq {
    fn from(x: &'a WasmPastaFq) -> Self {
        &x.0
    }
}

impl wasm_bindgen::describe::WasmDescribe for WasmPastaFq {
    fn describe() {
        <Vec<u8> as wasm_bindgen::describe::WasmDescribe>::describe()
    }
}

impl FromWasmAbi for WasmPastaFq {
    type Abi = <Vec<u8> as FromWasmAbi>::Abi;
    unsafe fn from_abi(js: Self::Abi) -> Self {
        let bytes: Vec<u8> = FromWasmAbi::from_abi(js);
        WasmPastaFq(Fq::deserialize_compressed(bytes.as_slice()).unwrap())
    }
}

impl IntoWasmAbi for WasmPastaFq {
    type Abi = <Vec<u8> as FromWasmAbi>::Abi;
    fn into_abi(self) -> Self::Abi {
        let mut bytes: Vec<u8> = vec![];
        self.0.serialize_compressed(&mut bytes).unwrap();
        bytes.into_abi()
    }
}

impl OptionIntoWasmAbi for WasmPastaFq {
    fn none() -> Self::Abi {
        <Vec<u8> as OptionIntoWasmAbi>::none()
    }
}

impl OptionFromWasmAbi for WasmPastaFq {
    fn is_none(abi: &Self::Abi) -> bool {
        <Vec<u8> as OptionFromWasmAbi>::is_none(abi)
    }
}

#[wasm_bindgen]
pub fn caml_pasta_fq_size_in_bits() -> isize {
    Fq_params::MODULUS_BITS as isize
}

#[wasm_bindgen]
pub fn caml_pasta_fq_size() -> WasmBigInteger256 {
    WasmBigInteger256(Fq_params::MODULUS)
}

#[wasm_bindgen]
pub fn caml_pasta_fq_add(x: WasmPastaFq, y: WasmPastaFq) -> WasmPastaFq {
    WasmPastaFq(x.0 + y.0)
}

#[wasm_bindgen]
pub fn caml_pasta_fq_sub(x: WasmPastaFq, y: WasmPastaFq) -> WasmPastaFq {
    WasmPastaFq(x.0 - y.0)
}

#[wasm_bindgen]
pub fn caml_pasta_fq_negate(x: WasmPastaFq) -> WasmPastaFq {
    WasmPastaFq(-x.0)
}

#[wasm_bindgen]
pub fn caml_pasta_fq_mul(x: WasmPastaFq, y: WasmPastaFq) -> WasmPastaFq {
    WasmPastaFq(x.0 * y.0)
}

#[wasm_bindgen]
pub fn caml_pasta_fq_div(x: WasmPastaFq, y: WasmPastaFq) -> WasmPastaFq {
    WasmPastaFq(x.0 / y.0)
}

#[wasm_bindgen]
pub fn caml_pasta_fq_inv(x: WasmPastaFq) -> Option<WasmPastaFq> {
    x.0.inverse().map(WasmPastaFq)
}

#[wasm_bindgen]
pub fn caml_pasta_fq_square(x: WasmPastaFq) -> WasmPastaFq {
    WasmPastaFq(x.0.square())
}

#[wasm_bindgen]
pub fn caml_pasta_fq_is_square(x: WasmPastaFq) -> bool {
    let s = x.0.pow(Fq_params::MODULUS_MINUS_ONE_DIV_TWO);
    s.is_zero() || s.is_one()
}

#[wasm_bindgen]
pub fn caml_pasta_fq_sqrt(x: WasmPastaFq) -> Option<WasmPastaFq> {
    x.0.sqrt().map(WasmPastaFq)
}

#[wasm_bindgen]
pub fn caml_pasta_fq_of_int(i: i32) -> WasmPastaFq {
    WasmPastaFq(Fq::from(i as u64))
}

#[wasm_bindgen]
pub fn caml_pasta_fq_to_string(x: WasmPastaFq) -> String {
    bigint_256::to_biguint(&x.0.into_bigint()).to_string()
}

#[wasm_bindgen]
pub fn caml_pasta_fq_of_string(s: String) -> Result<WasmPastaFq, JsValue> {
    let biguint = BigUint::parse_bytes(s.as_bytes(), 10)
        .ok_or(JsValue::from_str("caml_pasta_fq_of_string"))?;

    match Fq::from_bigint(bigint_256::of_biguint(&biguint)) {
        Some(x) => Ok(x.into()),
        None => Err(JsValue::from_str("caml_pasta_fq_of_string")),
    }
}

#[wasm_bindgen]
pub fn caml_pasta_fq_print(x: WasmPastaFq) {
    println!("{}", bigint_256::to_biguint(&(x.0.into_bigint())));
}

#[wasm_bindgen]
pub fn caml_pasta_fq_compare(x: WasmPastaFq, y: WasmPastaFq) -> i32 {
    match x.0.cmp(&y.0) {
        Less => -1,
        Equal => 0,
        Greater => 1,
    }
}

#[wasm_bindgen]
pub fn caml_pasta_fq_equal(x: WasmPastaFq, y: WasmPastaFq) -> bool {
    x.0 == y.0
}

#[wasm_bindgen]
pub fn caml_pasta_fq_random() -> WasmPastaFq {
    WasmPastaFq(UniformRand::rand(&mut rand::thread_rng()))
}

#[wasm_bindgen]
pub fn caml_pasta_fq_rng(i: i32) -> WasmPastaFq {
    // We only care about entropy here, so we force a conversion i32 -> u32.
    let i: u64 = (i as u32).into();
    let mut rng: StdRng = rand::SeedableRng::seed_from_u64(i);
    WasmPastaFq(UniformRand::rand(&mut rng))
}

#[wasm_bindgen]
pub fn caml_pasta_fq_to_bigint(x: WasmPastaFq) -> WasmBigInteger256 {
    WasmBigInteger256(x.0.into_bigint())
}

#[wasm_bindgen]
pub fn caml_pasta_fq_of_bigint(x: WasmBigInteger256) -> Result<WasmPastaFq, JsValue> {
    match Fq::from_bigint(x.0) {
        Some(x) => Ok(x.into()),
        None => Err(JsValue::from_str("caml_pasta_fq_of_bigint")),
    }
}

#[wasm_bindgen]
pub fn caml_pasta_fq_two_adic_root_of_unity() -> WasmPastaFq {
    WasmPastaFq(<Fq as FftField>::TWO_ADIC_ROOT_OF_UNITY)
}

#[wasm_bindgen]
pub fn caml_pasta_fq_domain_generator(log2_size: i32) -> WasmPastaFq {
    match Domain::new(1 << log2_size) {
        Some(x) => WasmPastaFq(x.group_gen),
        None => panic!("caml_pasta_fq_domain_generator"),
    }
}

#[wasm_bindgen]
pub fn caml_pasta_fq_to_bytes(x: WasmPastaFq) -> Vec<u8> {
    let len = core::mem::size_of::<Fq>();
    let mut str: Vec<u8> = vec![0; len];
    str.resize(len, 0);
    let str_as_fq: *mut Fq = str.as_mut_ptr().cast::<Fq>();
    unsafe {
        *str_as_fq = x.0;
    }
    str
}

#[wasm_bindgen]
pub fn caml_pasta_fq_of_bytes(x: &[u8]) -> WasmPastaFq {
    let len = core::mem::size_of::<Fq>();
    if x.len() != len {
        panic!("caml_pasta_fq_of_bytes");
    };
    let x = unsafe { *(x.as_ptr() as *const Fq) };
    WasmPastaFq(x)
}

#[wasm_bindgen]
pub fn caml_pasta_fq_deep_copy(x: WasmPastaFq) -> WasmPastaFq {
    x
}
