use crate::caml::{caml_bigstring::CamlBigstring, caml_bytes_string::CamlBytesString};
use ark_ff::{BigInteger as ark_BigInteger, BigInteger256};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::{
    cmp::Ordering::{Equal, Greater, Less},
    convert::{TryFrom, TryInto},
    fmt::{Display, Formatter},
    ops::Deref,
};
use num_bigint::BigUint;

//
// Handy constants
//

const BIGINT256_NUM_BITS: i32 = 256;
const BIGINT256_LIMB_BITS: i32 = 64;
const BIGINT256_LIMB_BYTES: i32 = BIGINT256_LIMB_BITS / 8;
const BIGINT256_NUM_LIMBS: i32 =
    (BIGINT256_NUM_BITS + BIGINT256_LIMB_BITS - 1) / BIGINT256_LIMB_BITS;

//
// Wrapper struct to implement OCaml bindings
//

#[derive(Clone, Copy, Debug, ocaml_gen::CustomType)]
pub struct CamlBigInteger256(pub BigInteger256);

impl From<BigInteger256> for CamlBigInteger256 {
    fn from(big: BigInteger256) -> Self {
        Self(big)
    }
}

unsafe impl<'a> ocaml::FromValue<'a> for CamlBigInteger256 {
    fn from_value(value: ocaml::Value) -> Self {
        let x: ocaml::Pointer<Self> = ocaml::FromValue::from_value(value);
        *x.as_ref()
    }
}

impl CamlBigInteger256 {
    unsafe extern "C" fn caml_pointer_finalize(v: ocaml::Raw) {
        let ptr = v.as_pointer::<Self>();
        ptr.drop_in_place()
    }

    unsafe extern "C" fn ocaml_compare(x: ocaml::Raw, y: ocaml::Raw) -> i32 {
        let x = x.as_pointer::<Self>();
        let y = y.as_pointer::<Self>();
        match x.as_ref().0.cmp(&y.as_ref().0) {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
        }
    }
}

ocaml::custom!(CamlBigInteger256 {
    finalize: CamlBigInteger256::caml_pointer_finalize,
    compare: CamlBigInteger256::ocaml_compare,
});

impl Deref for CamlBigInteger256 {
    type Target = BigInteger256;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

//
// BigUint handy methods
//

impl From<CamlBigInteger256> for BigUint {
    fn from(x: CamlBigInteger256) -> BigUint {
        x.0.into()
    }
}

impl From<&CamlBigInteger256> for BigUint {
    fn from(x: &CamlBigInteger256) -> BigUint {
        x.0.into()
    }
}

impl TryFrom<BigUint> for CamlBigInteger256 {
    type Error = String;

    fn try_from(x: BigUint) -> Result<Self, Self::Error> {
        Ok(Self(
            BigInteger256::try_from(x).map_err(|()| "Biginteger256 was too big")?,
        ))
    }
}

impl TryFrom<&BigUint> for CamlBigInteger256 {
    type Error = String;

    fn try_from(x: &BigUint) -> Result<Self, Self::Error> {
        Ok(Self(
            BigInteger256::try_from(x.clone()).map_err(|()| "Biginteger256 was too big")?,
        ))
    }
}

impl Display for CamlBigInteger256 {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{}", Into::<BigUint>::into(self))
    }
}

//
// OCaml stuff
//

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_bigint_256_of_numeral(
    s: CamlBytesString,
    _len: ocaml::Int,
    base: ocaml::Int,
) -> Result<CamlBigInteger256, ocaml::Error> {
    match BigUint::parse_bytes(
        s.0,
        base.try_into()
            .map_err(|_| ocaml::Error::Message("caml_bigint_256_of_numeral"))?,
    ) {
        Some(data) => CamlBigInteger256::try_from(data)
            .map_err(|_| ocaml::Error::Message("caml_bigint_256_of_numeral")),
        None => Err(ocaml::Error::Message("caml_bigint_256_of_numeral")),
    }
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_bigint_256_of_decimal_string(
    s: CamlBytesString,
) -> Result<CamlBigInteger256, ocaml::Error> {
    match BigUint::parse_bytes(s.0, 10) {
        Some(data) => CamlBigInteger256::try_from(data)
            .map_err(|_| ocaml::Error::Message("caml_bigint_256_of_decimal_string")),
        None => Err(ocaml::Error::Message("caml_bigint_256_of_decimal_string")),
    }
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_bigint_256_num_limbs() -> ocaml::Int {
    BIGINT256_NUM_LIMBS.try_into().unwrap()
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_bigint_256_bytes_per_limb() -> ocaml::Int {
    BIGINT256_LIMB_BYTES.try_into().unwrap()
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_bigint_256_div(x: CamlBigInteger256, y: CamlBigInteger256) -> CamlBigInteger256 {
    let x: BigUint = x.into();
    let y: BigUint = y.into();
    let res: BigUint = x / y;
    let inner: BigInteger256 = res.try_into().expect("BigUint division has a bug");
    inner.into()
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_bigint_256_compare(
    x: ocaml::Pointer<CamlBigInteger256>,
    y: ocaml::Pointer<CamlBigInteger256>,
) -> ocaml::Int {
    match x.as_ref().cmp(y.as_ref()) {
        Less => -1,
        Equal => 0,
        Greater => 1,
    }
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_bigint_256_print(x: CamlBigInteger256) {
    println!("{}", x)
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_bigint_256_to_string(x: CamlBigInteger256) -> String {
    x.to_string()
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_bigint_256_test_bit(
    x: ocaml::Pointer<CamlBigInteger256>,
    i: ocaml::Int,
) -> Result<bool, ocaml::Error> {
    match i.try_into() {
        Ok(i) => Ok(x.as_ref().get_bit(i)),
        Err(_) => Err(ocaml::Error::invalid_argument("caml_bigint_256_test_bit")
            .err()
            .unwrap()),
    }
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_bigint_256_to_bytes(
    x: ocaml::Pointer<CamlBigInteger256>,
) -> [u8; core::mem::size_of::<BigInteger256>()] {
    let mut res = [0u8; core::mem::size_of::<BigInteger256>()];
    x.as_ref().0.serialize_compressed(&mut res[..]).unwrap();
    res
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_bigint_256_of_bytes(x: &[u8]) -> Result<CamlBigInteger256, ocaml::Error> {
    let len = core::mem::size_of::<BigInteger256>();
    if x.len() != len {
        ocaml::Error::failwith("caml_bigint_256_of_bytes")?;
    };
    let result = BigInteger256::deserialize_compressed(&mut &*x)
        .map_err(|_| ocaml::Error::Message("deserialization error"))?;
    Ok(CamlBigInteger256(result))
}

/// Serialize `x` into `buf[pos .. pos + 32]`, the same bytes as
/// `caml_bigint_256_to_bytes`, without allocating. Raises `Invalid_argument`
/// when the window does not fit in `buf`.
#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_bigint_256_to_bytes_into(
    x: ocaml::Pointer<CamlBigInteger256>,
    mut buf: CamlBigstring,
    pos: ocaml::Int,
) -> Result<(), ocaml::Error> {
    let dst = buf.slice_mut(
        pos,
        core::mem::size_of::<BigInteger256>(),
        "caml_bigint_256_to_bytes_into",
    )?;
    x.as_ref().0.serialize_compressed(dst).unwrap();
    Ok(())
}

/// Deserialize from `buf[pos .. pos + 32]`, the same semantics as
/// `caml_bigint_256_of_bytes`, without copying the bytes out first. Raises
/// `Invalid_argument` when the window does not fit in `buf`.
#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_bigint_256_of_bytes_from(
    buf: CamlBigstring,
    pos: ocaml::Int,
) -> Result<CamlBigInteger256, ocaml::Error> {
    let src = buf.slice(
        pos,
        core::mem::size_of::<BigInteger256>(),
        "caml_bigint_256_of_bytes_from",
    )?;
    let result = BigInteger256::deserialize_compressed(src)
        .map_err(|_| ocaml::Error::Message("deserialization error"))?;
    Ok(CamlBigInteger256(result))
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_bigint_256_deep_copy(x: CamlBigInteger256) -> CamlBigInteger256 {
    x
}

//
// Tests
//

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigUint;

    #[test]
    fn biguint() {
        let x = 10000.to_biguint().unwrap();
        println!("biguint.to_string: {}", x);
        let y = CamlBigInteger256::try_from(x.clone()).unwrap();
        println!("camlbigint.to_string: {}", y);
        //assert!(&y.to_string() == "10000");
        let x2: BigUint = y.into();
        assert!(x2 == x);
        println!("biguint.to_string: {}", x2);
    }

    /// The in-place path writes the same bytes as `to_bytes`, at the offset,
    /// and reads them back.
    #[test]
    fn in_place_bytes_match_to_bytes() {
        let x = BigInteger256::from(0xdead_beef_u64);
        let len = core::mem::size_of::<BigInteger256>();

        let mut expected = vec![0u8; len];
        x.serialize_compressed(&mut expected[..]).unwrap();

        let mut buf = vec![0xffu8; 3 * len];
        let range =
            crate::caml::caml_bigstring::checked_range(buf.len(), len as ocaml::Int, len, "t")
                .unwrap();
        x.serialize_compressed(&mut buf[range.clone()]).unwrap();

        assert_eq!(&buf[range.clone()], &expected[..]);
        assert!(buf[..len].iter().all(|&b| b == 0xff));
        assert!(buf[2 * len..].iter().all(|&b| b == 0xff));
        assert_eq!(
            BigInteger256::deserialize_compressed(&buf[range]).unwrap(),
            x
        );
    }
}
