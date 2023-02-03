//! Routes to the best available MSM implementation.

use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};

/// Fast MSM implementations using GPU-acceleration.
//#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub mod msm {
    use ark_ec::AffineCurve;
    use ark_ff::ToBytes as _;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use mina_curves::pasta::curves::pallas::LegacyPallas;
    use mina_curves::pasta::curves::vesta::LegacyVesta;
    use pasta_curves::arithmetic::FieldExt;
    use pasta_curves::group::Curve;
    use pasta_curves::group::{ff::PrimeField as _, GroupEncoding};

    use super::*;

    //
    // Traits for scalars
    //

    /// TKTK
    // TODO: bonus point if you can have default implementations hold the logic here
    pub trait ToOtherScalar {
        /// The other curve's type
        type Other: FieldExt + pasta_curves::group::ff::Field;

        /// The conversion to that type
        fn to_other(&self) -> Self::Other;

        /// The conversion back from that type
        fn from_other(other: &Self::Other) -> Self;
    }

    impl ToOtherScalar for Fp {
        type Other = pasta_curves::vesta::Scalar;

        fn to_other(&self) -> Self::Other {
            let mut bytes = [0u8; 64];
            // arkwork points to bytes
            self.write(&mut bytes[..]).unwrap();

            // TODO: use our own helper
            Self::Other::from_bytes_wide(&bytes)
        }

        fn from_other(other: &Self::Other) -> Self {
            let repr = other.to_repr();
            Self::deserialize(&repr[..]).unwrap()
        }
    }

    impl ToOtherScalar for Fq {
        type Other = pasta_curves::pallas::Scalar;

        fn to_other(&self) -> Self::Other {
            let mut bytes = [0u8; 64];
            // arkwork points to bytes
            self.write(&mut bytes[..]).unwrap();

            // TODO: use our own helper
            Self::Other::from_bytes_wide(&bytes)
        }

        fn from_other(other: &Self::Other) -> Self {
            let repr = other.to_repr();
            Self::deserialize(&repr[..]).unwrap()
        }
    }

    //
    // Traits for elliptic curve affine points
    //

    /// TKTK
    // TODO: bonus point if you can have default implementations hold the logic here
    pub trait ToOtherAffine: AffineCurve {
        /// The other curve's type.
        type Other;

        /// The conversion to that type.
        fn to_other(&self) -> Self::Other;

        /// The conversion back from that type.
        fn from_other(other: &Self::Other) -> Self;
    }

    impl ToOtherAffine for Pallas {
        type Other = pasta_curves::pallas::Affine;

        fn to_other(&self) -> Self::Other {
            // we base this code on the assumption that the odd bit is in the last byte
            assert_eq!(self.serialized_size(), 33);

            // the other library encodes it in the MSB of the last byte instead:
            //
            // ```
            // fn to_bytes(&self) -> [u8; 32] {
            //     if bool::from(self.is_identity()) {
            //         [0; 32]
            //     } else {
            //         let (x, y) = (self.x, self.y);
            //         let sign = y.is_odd().unwrap_u8() << 7;
            //         let mut xbytes = x.to_repr();
            //         xbytes[31] |= sign;
            //         xbytes
            //     }
            // }
            // ```

            let mut bytes = vec![];
            self.serialize(&mut bytes).unwrap();

            let is_odd = if bytes[32] == 1 { 1 << 7 } else { 0 };
            bytes[32] |= is_odd;

            let bytes: [u8; 32] = bytes[..32].try_into().unwrap();

            if cfg!(debug_assertions) {
                let res = pasta_curves::pallas::Affine::from_bytes(&bytes).unwrap();
                let res2 = pasta_curves::pallas::Affine::from_bytes_unchecked(&bytes).unwrap();
                assert_eq!(res, res2);
                res2
            } else {
                pasta_curves::pallas::Affine::from_bytes_unchecked(&bytes).unwrap()
            }
        }

        fn from_other(other: &Self::Other) -> Self {
            let mut bytes = other.to_bytes().to_vec();

            // as commented in the other function, the last byte's MSB contains the odd bit.
            // arkworks expects it to be in an extra byte.
            if bytes[31] >> 7 == 1 {
                bytes[31] &= 0b0111_1111;
                bytes.push(1);
            } else {
                bytes.push(0);
            }

            Pallas::deserialize(&*bytes).unwrap()
        }
    }

    impl ToOtherAffine for Vesta {
        type Other = pasta_curves::vesta::Affine;

        fn to_other(&self) -> Self::Other {
            // we base this code on the assumption that the odd bit is in the last byte
            assert_eq!(self.serialized_size(), 33);

            // the other library encodes it in the MSB of the last byte instead:
            //
            // ```
            // fn to_bytes(&self) -> [u8; 32] {
            //     if bool::from(self.is_identity()) {
            //         [0; 32]
            //     } else {
            //         let (x, y) = (self.x, self.y);
            //         let sign = y.is_odd().unwrap_u8() << 7;
            //         let mut xbytes = x.to_repr();
            //         xbytes[31] |= sign;
            //         xbytes
            //     }
            // }
            // ```

            let mut bytes = vec![];
            self.serialize(&mut bytes).unwrap();

            let is_odd = if bytes[32] == 1 { 1 << 7 } else { 0 };
            bytes[32] |= is_odd;

            let bytes: [u8; 32] = bytes[..32].try_into().unwrap();

            if cfg!(debug_assertions) {
                let res = pasta_curves::vesta::Affine::from_bytes(&bytes).unwrap();
                let res2 = pasta_curves::vesta::Affine::from_bytes_unchecked(&bytes).unwrap();
                assert_eq!(res, res2);
                res2
            } else {
                pasta_curves::vesta::Affine::from_bytes_unchecked(&bytes).unwrap()
            }
        }

        fn from_other(other: &Self::Other) -> Self {
            let mut bytes = other.to_bytes().to_vec();

            // as commented in the other function, the last byte's MSB contains the odd bit.
            // arkworks expects it to be in an extra byte.
            if bytes[31] >> 7 == 1 {
                bytes[31] &= 0b0111_1111;
                bytes.push(1);
            } else {
                bytes.push(0);
            }

            Vesta::deserialize(&*bytes).unwrap()
        }
    }

    //
    // MSM
    //

    /// TKTK
    // TODO: bonus point if you can move the logic to a default impl
    pub trait MultiScalarMultiplication: ToOtherAffine {
        /// MSM implementation
        fn msm(bases: &[Self], scalars: &[Self::ScalarField]) -> Self;
    }

    impl MultiScalarMultiplication for Pallas {
        fn msm(bases: &[Self], scalars: &[Self::ScalarField]) -> Self {
            // convert arkworks points/scalars to pasta_curves types
            let points: Vec<_> = bases.iter().map(ToOtherAffine::to_other).collect();
            let scalars: Vec<_> = scalars.iter().map(ToOtherScalar::to_other).collect();

            let res = pasta_msm::pallas(&points, &scalars);

            Pallas::from_other(&res.to_affine())
        }
    }

    impl MultiScalarMultiplication for Vesta {
        fn msm(bases: &[Self], scalars: &[Self::ScalarField]) -> Self {
            // convert arkworks points/scalars to pasta_curves types
            let points: Vec<_> = bases.iter().map(ToOtherAffine::to_other).collect();
            let scalars: Vec<_> = scalars.iter().map(ToOtherScalar::to_other).collect();

            let res = pasta_msm::vesta(&points, &scalars);

            Vesta::from_other(&res.to_affine())
        }
    }

    //
    // Due to the trait KimchiCurve (see in kimchi) we need to implement this for the legacy curves
    //

    impl ToOtherAffine for LegacyVesta {
        type Other = pasta_curves::vesta::Affine;

        fn to_other(&self) -> Self::Other {
            unreachable!()
        }

        fn from_other(_other: &Self::Other) -> Self {
            unreachable!()
        }
    }

    impl ToOtherAffine for LegacyPallas {
        type Other = pasta_curves::pallas::Affine;

        fn to_other(&self) -> Self::Other {
            unreachable!()
        }

        fn from_other(_other: &Self::Other) -> Self {
            unreachable!()
        }
    }

    impl MultiScalarMultiplication for LegacyVesta {
        fn msm(_bases: &[Self], _scalars: &[Self::ScalarField]) -> Self {
            unreachable!()
        }
    }

    impl MultiScalarMultiplication for LegacyPallas {
        fn msm(_bases: &[Self], _scalars: &[Self::ScalarField]) -> Self {
            unreachable!()
        }
    }

    // /// Do we need this function now?
    // pub fn fast_msm<G: MultiScalarMultiplication>(bases: &[G], scalars: &[G::ScalarField]) -> G {
    //     G::msm(&bases, &scalars)
    // }

    //
    // Sanity checks
    //

    // TODO: bonus point for using proptests
    #[cfg(test)]
    mod tests {
        use std::ops::Mul;

        use super::*;
        use ark_ec::ProjectiveCurve as _;
        use ark_ec::{msm::VariableBaseMSM, AffineCurve};
        use ark_ff::{FftField, PrimeField};
        use ark_std::{test_rng, UniformRand};
        use pasta_curves::arithmetic::FieldExt;

        //
        // Test that scalar conversion works
        //

        fn test_scalars_conv_generic<F: FftField + ToOtherScalar>() {
            {
                // check a root of unity
                let arkworks_root = F::get_root_of_unity(2).unwrap();
                println!("{arkworks_root}");
                let other_fq = arkworks_root.to_other();
                println!("{:?}", other_fq);

                // multiply by order
                let one = arkworks_root.pow(&[4u64]);
                assert!(one.is_one());
                println!("one: {one}");

                // same with other
                let one2 = other_fq.pow(&[0u64, 0, 0, 4]);
                println!("one: {:?}", one2);
                // TODO: not sure how to check that the other is one too
            }

            // do the same with a random value
            let x: F = UniformRand::rand(&mut test_rng());
            let y: F = UniformRand::rand(&mut test_rng());
            let res = x * y;

            let other_x = x.to_other();
            let other_y = y.to_other();
            let other_res = other_x * other_y;

            let res_back = F::from_other(&other_res);
            assert_eq!(res, res_back);
        }

        // TODO: this only tests Fq, not Fp
        #[test]
        fn test_arkworks_pasta_scalar_conversion() {
            test_scalars_conv_generic::<Fq>();
            test_scalars_conv_generic::<Fp>();
        }
        //
        // Test that point conversion works
        //

        // TODO: make a generic test like the tests around
        #[test]
        fn test_arkworks_pasta_point_conversion() {
            // generate random arkworks pallas point
            let x = Pallas::prime_subgroup_generator();
            let y = x.mul(Fq::from(2u64));

            let other_x = x.to_other();
            let other_y = other_x.mul(&Fq::from(2u64).to_other());
            let other_y_bis = other_x.mul(&pasta_curves::Fq::from(2u64));

            assert_eq!(other_y, other_y_bis);

            let y_back = Pallas::from_other(&other_y.to_affine());
            assert_eq!(y, y_back);
        }

        //
        // Test that MSM works
        //

        fn test_msm_generic<G: MultiScalarMultiplication>() {
            let scalars = vec![G::ScalarField::from(2u64), G::ScalarField::from(3u8)];
            let points = vec![G::prime_subgroup_generator(), G::prime_subgroup_generator()];

            let res = VariableBaseMSM::multi_scalar_mul(
                &points,
                &scalars.iter().map(|x| x.into_repr()).collect::<Vec<_>>(),
            );

            let other_res = G::msm(&points, &scalars);

            assert_eq!(res.into_affine(), other_res);
        }

        #[test]
        fn test_msm() {
            test_msm_generic::<Pallas>();
            test_msm_generic::<Vesta>();
        }
    }
}

// #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
// pub mod msm {
//     use super::*;

//     pub fn pallas_msm(bases: &[G], scalars: &[<G::ScalarField as PrimeField>::BigInt]) -> Self {

// VariableBaseMSM::multi_scalar_mul(
//     &[&g[0..n], &[self.h, u]].concat(),
//     &[&a[n..], &[rand_l, inner_prod(a_hi, b_lo)]]
//         .concat()
//         .iter()
//         .map(|x| x.into_repr())
//         .collect::<Vec<_>>(),
// )
// .into_affine();

//         VariableBaseMSM::multi_scalar_mul();
//     }
// }
