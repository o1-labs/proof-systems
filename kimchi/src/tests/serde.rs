use crate::{
    bench::BenchmarkCtx,
    circuits::{
        polynomials::generic::testing::{create_circuit, fill_in_witness},
        wires::COLUMNS,
    },
    proof::ProverProof,
    prover_index::testing::new_index_for_test,
    verifier::verify,
    verifier_index::VerifierIndex,
};
use ark_ec::short_weierstrass::Affine;
use ark_ff::Zero;
use groupmap::GroupMap;
use mina_curves::pasta::{Fp, Vesta, VestaConfig};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use poly_commitment::{commitment::CommitmentCurve, srs::SRS};
use std::array;
use std::time::Instant;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaConfig, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

#[cfg(test)]
mod tests {

    use ark_ec::models::short_weierstrass::SWCurveConfig;
    use std::{env, fs, path::PathBuf};

    use ark_ff::PrimeField;
    use ark_serialize::{Read, Write};
    use mina_curves::pasta::PallasConfig;
    use num_traits::pow;

    use super::*;

    #[test]
    fn test_rmp_serde() {
        let ctx = BenchmarkCtx::new(1 << 4);

        let (proof, public_input) = ctx.create_proof();

        // small check of proof being serializable
        // serialize a proof
        let ser_pf = rmp_serde::to_vec(&proof).unwrap();
        println!("proof size: {} bytes", ser_pf.len());

        // deserialize the proof
        let de_pf: ProverProof<Vesta> = rmp_serde::from_slice(&ser_pf).unwrap();

        // verify the deserialized proof (must accept the proof)
        ctx.batch_verification(&vec![(de_pf, public_input)]);
    }

    #[test]
    pub fn test_serialization() {
        let public = vec![Fp::from(3u8); 5];
        let gates = create_circuit(0, public.len());

        // create witness
        let mut witness: [Vec<Fp>; COLUMNS] = array::from_fn(|_| vec![Fp::zero(); gates.len()]);
        fill_in_witness(0, &mut witness, &public);

        let index = new_index_for_test(gates, public.len());
        let verifier_index = index.verifier_index();

        let verifier_index_serialize =
            serde_json::to_string(&verifier_index).expect("couldn't serialize index");

        // verify the circuit satisfiability by the computed witness
        index.verify(&witness, &public).unwrap();

        // add the proof to the batch
        let group_map = <Vesta as CommitmentCurve>::Map::setup();
        let proof =
            ProverProof::create::<BaseSponge, ScalarSponge>(&group_map, witness, &[], &index)
                .unwrap();

        // deserialize the verifier index
        let mut verifier_index_deserialize: VerifierIndex<Affine<VestaConfig>> =
            serde_json::from_str(&verifier_index_serialize).unwrap();

        // add srs with lagrange bases
        let mut srs = SRS::<Affine<VestaConfig>>::create(verifier_index.max_poly_size);
        srs.add_lagrange_basis(verifier_index.domain);
        verifier_index_deserialize.powers_of_alpha = index.powers_of_alpha;
        verifier_index_deserialize.linearization = index.linearization;

        // verify the proof
        let start = Instant::now();
        verify::<Vesta, BaseSponge, ScalarSponge>(
            &group_map,
            &verifier_index_deserialize,
            &proof,
            &public,
        )
        .unwrap();
        println!("- time to verify: {}ms", start.elapsed().as_millis());
    }

    #[test]
    pub fn test_srs_serialization() {
        fn create_or_check_srs<T: SWCurveConfig + Clone>(curve: &str, exp: usize)
        where
            T::BaseField: PrimeField,
        {
            let srs = SRS::<Affine<T>>::create(pow(2, exp));

            let base_path = env::var("CARGO_MANIFEST_DIR").expect("failed to get manifest path");
            let srs_path: PathBuf = [base_path, "../srs".into(), curve.to_string() + ".srs"]
                .iter()
                .collect();

            // Safety check (comment to manually create new SRS)
            if !srs_path.exists() {
                panic!("Missing SRS file: {}", srs_path.display());
            }

            if !srs_path.exists() {
                // Create SRS
                let mut file = fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(srs_path)
                    .expect("failed to open file");

                let srs_bytes = rmp_serde::to_vec(&srs).unwrap();
                file.write_all(&srs_bytes).expect("failed to write file");
                file.flush().expect("failed to flush file");
            } else {
                // Check SRS
                let mut file = fs::OpenOptions::new()
                    .read(true)
                    .open(srs_path)
                    .expect("failed to open file");

                let mut bytes = vec![];
                file.read_to_end(&mut bytes).expect("failed to read file");
                let srs_serde: SRS<Affine<T>> = rmp_serde::from_slice(&bytes).unwrap();
                assert_eq!(srs.g, srs_serde.g);
                assert_eq!(srs.h, srs_serde.h);
            }
        }

        create_or_check_srs::<VestaConfig>("vesta", 16);
        create_or_check_srs::<PallasConfig>("pallas", 16);
    }
}
