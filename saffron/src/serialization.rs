use ark_ff::{BigInteger, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};

// For injectivity, you can only use this on inputs of length at most
// 'F::MODULUS_BIT_SIZE / 8', e.g. for Vesta this is 31.
pub fn encode<Fp: PrimeField>(bytes: &[u8]) -> Fp {
    Fp::from_be_bytes_mod_order(bytes)
}

pub fn decode<Fp: PrimeField>(x: Fp) -> Vec<u8> {
    x.into_bigint().to_bytes_be()
}

pub fn serialize_vec<F: Field>(xs: &[F]) -> Vec<u8> {
    let n = xs.serialized_size(Compress::Yes);
    let mut writer = Vec::with_capacity(n);
    xs.serialize_compressed(&mut writer)
        .expect("Failed to serialize field elements");
    writer
}

pub fn deserialize_vec<F: PrimeField>(bytes: &[u8]) -> Vec<F> {
    Vec::<F>::deserialize_compressed(bytes).expect("Failed to deserialize field elements")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;
    use mina_curves::pasta::Fp;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_round_trip_from_bytes(xs in any::<[u8;31]>())
          { let n : Fp = encode(&xs);
            let ys : [u8; 31] = decode(n).as_slice()[1..32].try_into().unwrap();
            prop_assert_eq!(xs, ys);
          }
    }

    proptest! {
        #[test]
        fn test_round_trip_from_fp(
            x in prop::strategy::Just(Fp::rand(&mut ark_std::rand::thread_rng()))
        ) {
            let bytes = decode(x);
            let y = encode(&bytes);
            prop_assert_eq!(x,y);
        }
    }

    fn fp_strategy() -> impl Strategy<Value = Fp> {
        prop::strategy::Just(Fp::rand(&mut ark_std::rand::thread_rng()))
    }

    proptest! {
        #[test]
        fn test_round_trip_vec(
            xs in prop::collection::vec(fp_strategy(), 0..100)
        ) {
            let bytes = serialize_vec(&xs);
            let ys = deserialize_vec(&bytes);
            prop_assert_eq!(xs,ys);
        }
    }
}
