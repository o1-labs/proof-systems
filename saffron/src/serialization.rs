use mina_curves::pasta::Fp;
use num_bigint::BigUint;

pub fn from_bytes(bs: &[u8]) -> Fp {
    BigUint::from_bytes_be(bs).into()
}

pub fn to_bytes(f: Fp) -> Vec<u8> {
    BigUint::from(f).to_bytes_be()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_round_trip_from_bytes(bs in any::<[u8;31]>())
          { let n = from_bytes(&bs);
            let bs2 = to_bytes(n);
            prop_assert_eq!(bs, bs2.as_slice());
          }
    }

    use ark_std::UniformRand;

    proptest! {
        #[test]
        fn test_round_trip_from_fp(
            // Generate a valid field element using the curve's RNG
            a in prop::strategy::Just(Fp::rand(&mut ark_std::rand::thread_rng()))
        ) {
            let bs = to_bytes(a);
            let a2 = from_bytes(&bs);
            prop_assert_eq!(a, a2);
        }
    }
}
