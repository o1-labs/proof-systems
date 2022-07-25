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
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ff::Zero;
use array_init::array_init;
use commitment_dlog::{commitment::CommitmentCurve, srs::SRS};
use groupmap::GroupMap;
use mina_curves::pasta::{
    fp::Fp,
    vesta::{Vesta, VestaParameters},
};
use oracle::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use std::time::Instant;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_rmp_serde() {
        let ctx = BenchmarkCtx::new(1 << 4);

        let proof = ctx.create_proof();

        // small check of proof being serializable
        // serialize a proof
        let ser_pf = rmp_serde::to_vec(&proof).unwrap();
        println!("proof size: {} bytes", ser_pf.len());

        // deserialize the proof
        let de_pf: ProverProof<Vesta> = rmp_serde::from_slice(&ser_pf).unwrap();

        // verify the deserialized proof (must accept the proof)
        ctx.batch_verification(vec![de_pf.clone()]);
    }

    #[test]
    pub fn test_serialization() {
        let public = vec![Fp::from(3u8); 5];
        let gates = create_circuit(0, public.len());

        // create witness
        let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![Fp::zero(); gates.len()]);
        fill_in_witness(0, &mut witness, &public);

        let index = new_index_for_test(gates, public.len());
        let verifier_index = index.verifier_index();

        let verifier_index_serialize =
            serde_json::to_string(&verifier_index).expect("couldn't serialize index");

        // verify the circuit satisfiability by the computed witness
        index.cs.verify::<Vesta>(&witness, &public).unwrap();

        // add the proof to the batch
        let group_map = <Vesta as CommitmentCurve>::Map::setup();
        let proof =
            ProverProof::create::<BaseSponge, ScalarSponge>(&group_map, witness, &[], &index)
                .unwrap();

        // deserialize the verifier index
        let mut verifier_index_deserialize: VerifierIndex<GroupAffine<VestaParameters>> =
            serde_json::from_str(&verifier_index_serialize).unwrap();

        // add srs with lagrange bases
        let mut srs = SRS::<GroupAffine<VestaParameters>>::create(verifier_index.max_poly_size);
        srs.add_lagrange_basis(verifier_index.domain);
        verifier_index_deserialize.powers_of_alpha = index.powers_of_alpha;
        verifier_index_deserialize.linearization = index.linearization;

        // verify the proof
        let start = Instant::now();
        verify::<Vesta, BaseSponge, ScalarSponge>(&group_map, &verifier_index_deserialize, &proof)
            .unwrap();
        println!("- time to verify: {}ms", start.elapsed().as_millis());
    }
}
