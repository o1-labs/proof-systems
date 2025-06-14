use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::UniformRand;
use paste::paste;
use rand::rngs::StdRng;

use wasm_bindgen::prelude::*;

macro_rules! impl_projective {
    ($name: ident,
     $GroupProjective: ty,
     $CamlG: ty,
     $CamlScalarField: ty,
     $BaseField: ty,
     $CamlBaseField: ty,
     $Projective: ty) => {

        paste! {
            #[wasm_bindgen]
            pub fn [<caml_ $name:snake _one>]() -> $GroupProjective {
                $Projective::generator().into()
            }

            #[wasm_bindgen]
            pub fn [<caml_ $name:snake _add>](
                x: &$GroupProjective,
                y: &$GroupProjective,
            ) -> $GroupProjective {
                x.as_ref() + y.as_ref()
            }

            #[wasm_bindgen]
            pub fn [<caml_ $name:snake _sub>](
                x: &$GroupProjective,
                y: &$GroupProjective,
            ) -> $GroupProjective {
                x.as_ref() - y.as_ref()
            }

            #[wasm_bindgen]
            pub fn [<caml_ $name:snake _negate>](
                x: &$GroupProjective,
            ) -> $GroupProjective {
                -(*x.as_ref())
            }

            #[wasm_bindgen]
            pub fn [<caml_ $name:snake _double>](
                x: &$GroupProjective,
            ) -> $GroupProjective {
                x.as_ref().double().into()
            }

            #[wasm_bindgen]
            pub fn [<caml_ $name:snake _scale>](
                x: &$GroupProjective,
                y: $CamlScalarField,
            ) -> $GroupProjective {
                let y: ark_ff::BigInteger256 = y.0.into();
                x.as_ref().mul_bigint(&y).into()
            }

            #[wasm_bindgen]
            pub fn [<caml_ $name:snake _random>]() -> $GroupProjective {
                let rng = &mut rand::rngs::OsRng;
                let proj: $Projective = UniformRand::rand(rng);
                proj.into()
            }

            #[wasm_bindgen]
            pub fn [<caml_ $name:snake _rng>](i: u32) -> $GroupProjective {
                // We only care about entropy here, so we force a conversion i32 -> u32.
                let i: u64 = (i as u32).into();
                let mut rng: StdRng = rand::SeedableRng::seed_from_u64(i);
                let proj: $Projective = UniformRand::rand(&mut rng);
                proj.into()
            }

            // improper_ctypes_definitions is allowed here because the CamlBase/ScalarField struct
            // already has #[repr(C)] in its definition
            #[allow(improper_ctypes_definitions)]
            #[wasm_bindgen]
            pub extern "C" fn [<caml_ $name:snake _endo_base>]() -> $CamlBaseField {
                let (endo_q, _endo_r) = poly_commitment::ipa::endos::<GAffine>();
                endo_q.into()
            }

            // improper_ctypes_definitions is allowed here because the CamlBase/ScalarField struct
            // already has #[repr(C)] in its definition
            #[allow(improper_ctypes_definitions)]
            #[wasm_bindgen]
            pub extern "C" fn [<caml_ $name:snake _endo_scalar>]() -> $CamlScalarField {
                let (_endo_q, endo_r) = poly_commitment::ipa::endos::<GAffine>();
                endo_r.into()
            }

            #[wasm_bindgen]
            pub fn [<caml_ $name:snake _to_affine>](
                x: &$GroupProjective
                ) -> $CamlG {
                x.as_ref().into_affine().into()
            }

            #[wasm_bindgen]
            pub fn [<caml_ $name:snake _of_affine>](x: $CamlG) -> $GroupProjective {
                Into::<GAffine>::into(x).into_group().into()
            }

            #[wasm_bindgen]
            pub fn [<caml_ $name:snake _of_affine_coordinates>](x: $CamlBaseField, y: $CamlBaseField) -> $GroupProjective {
                let res = $Projective::new_unchecked(x.into(), y.into(), <$BaseField as ark_ff::One>::one());
                res.into()
            }

            #[wasm_bindgen]
            pub fn [<caml_ $name:snake _affine_deep_copy>](x: $CamlG) -> $CamlG {
                x
            }
        }
    }
}

pub mod pallas {
    use super::*;
    use arkworks::{WasmGPallas, WasmPallasGProjective, WasmPastaFp, WasmPastaFq};
    use mina_curves::pasta::{Fp, Pallas as GAffine, ProjectivePallas};

    impl_projective!(
        pallas,
        WasmPallasGProjective,
        WasmGPallas,
        WasmPastaFq,
        Fp,
        WasmPastaFp,
        ProjectivePallas
    );
}

pub mod vesta {
    use super::*;
    use arkworks::{WasmGVesta, WasmPastaFp, WasmPastaFq, WasmVestaGProjective};
    use mina_curves::pasta::{Fq, ProjectiveVesta, Vesta as GAffine};

    impl_projective!(
        vesta,
        WasmVestaGProjective,
        WasmGVesta,
        WasmPastaFp,
        Fq,
        WasmPastaFq,
        ProjectiveVesta
    );
}
