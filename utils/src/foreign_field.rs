use std::fmt::Display;

use crate::field_helpers::FieldHelpers;
use ark_ff::FftField;
use array_init::array_init;
use num_bigint::BigUint;

pub const LIMB_BITS: u32 = 88;

pub const LIMB_COUNT: usize = 3;

/// The foreign field modulus of secp256k1 is the prime number (in big endian)
/// FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
/// given by the computation 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
/// more information here  https://en.bitcoin.it/wiki/Secp256k1
pub const FOREIGN_MOD: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
];
pub const FOREIGN_BITS: usize = 8 * FOREIGN_MOD.len(); // 256 bits

#[derive(Debug, Clone, Copy)]
pub struct ForeignElement<F, const N: usize> {
    /// limbs in little endian order
    pub limbs: [F; N],
    /// number of limbs used for the foreign field element
    pub len: usize,
}

impl<F: FftField, const N: usize> ForeignElement<F, N> {
    /// Initializes a new foreign element from a big unsigned integer
    pub fn new_from_big(big: BigUint) -> Self {
        let vec = ForeignElement::<F, N>::big_to_vec(big);

        // create an array of N native elements containing the limbs
        // until the array is full in big endian, so most significant
        // limbs may be zero if the big number is smaller
        let limbs = {
            let mut ini = [F::zero(); N];
            for i in 0..N {
                if i < vec.len() {
                    ini[i] = vec[i]
                }
            }
            ini
        };
        Self {
            limbs,
            len: limbs.len(),
        }
    }

    /// Initializes a new foreign element from a set of bytes in big endian
    pub fn new_from_be(bytes: &[u8]) -> Self {
        Self::new_from_big(BigUint::from_bytes_be(bytes))
    }

    /// Obtains the big integer representation of the foreign field element
    pub fn to_big(&self) -> BigUint {
        let mut bytes = vec![];
        for limb in self.limbs {
            bytes.extend_from_slice(&limb.to_bytes());
        }
        BigUint::from_bytes_le(&bytes)
    }

    /// Split a foreign field element into a vector of `LIMB_BITS` bits field elements of type `F` in little-endian.
    /// Right now it is written so that it gives `LIMB_COUNT` limbs, even if it fits in less bits.
    fn big_to_vec(fe: BigUint) -> Vec<F> {
        //let mut bytes = fe.to_bytes_le();
        let bytes = fe.to_bytes_le();
        //pad_zeros_le(&mut bytes, LIMB_BITS as usize * LIMB_COUNT / 8);
        let chunks: Vec<&[u8]> = bytes.chunks((LIMB_BITS / 8).try_into().unwrap()).collect();
        chunks
            .iter()
            .map(|chunk| F::from_random_bytes(chunk).expect("failed to deserialize"))
            .collect()
    }
}

impl<F: FftField> ForeignElement<F, 3> {
    /// Creates a new foreign element from an array containing 3 limbs
    pub fn new(limbs: [F; 3]) -> Self {
        Self { limbs, len: 3 }
    }

    pub fn lo(&self) -> &F {
        &self.limbs[0]
    }

    pub fn mi(&self) -> &F {
        &self.limbs[1]
    }

    pub fn hi(&self) -> &F {
        &self.limbs[2]
    }
}

impl<F: FftField, const N: usize> Display for ForeignElement<F, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();
        let order = ["lo", "mi", "hi"];
        s += "{ ";
        for (i, limb) in self.limbs.iter().enumerate() {
            let hex = limb.to_hex();
            let len = LIMB_BITS / 8 * 2;
            s += &(order[i % N].to_owned() + ": ");
            s.push_str(&hex[0..len as usize]);
            if i < N - 1 {
                s += " , ";
            }
        }
        s += " }";
        write!(f, "{}", s)
    }
}

/*
pub fn pad_zeros_le(le: &mut Vec<u8>, total: usize) {
    let len = le.len();
    if total > len {
        le.extend(vec![0; total - len]);
    }
}

/// Split a foreign field element into a vector of `LIMB_BITS` bits field elements of type `F` in little-endian.
/// Right now it is written so that it gives `LIMB_COUNT` limbs, even if it fits in less bits.
pub fn foreign_to_limbs<F: FftField>(fe: BigUint) -> Vec<F> {
    println!("fe: {:?}", fe);
    let mut bytes = fe.to_bytes_le();
    pad_zeros_le(&mut bytes, LIMB_BITS as usize * LIMB_COUNT / 8);
    let chunks: Vec<&[u8]> = bytes.chunks((LIMB_BITS / 8).try_into().unwrap()).collect();
    chunks
        .iter()
        .map(|chunk| F::from_random_bytes(chunk).expect("failed to deserialize"))
        .collect()
}

/// Obtains an array of length 3 of the limbs of a foreign field element
pub fn vec_to_limbs<F: FftField>(vec: &[F]) -> [F; 3] {
    let mut limbs = [F::zero(); 3];
    for (i, limb) in vec.iter().enumerate() {
        limbs[i] = *limb;
    }
    limbs
}

/// Build a [BigUint] number from a set of limbs in little-endian order
pub fn limbs_to_foreign<F: FftField>(limbs: &[F]) -> BigUint {
    let mut bytes = vec![];
    for limb in limbs {
        bytes.extend_from_slice(&limb.to_bytes());
    }
    BigUint::from_bytes_le(&bytes)
}
*/
