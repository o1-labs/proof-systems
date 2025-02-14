use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::UniformRand;
use kimchi::{curve::KimchiCurve, groupmap::GroupMap};
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge, FqSponge};
use once_cell::sync::Lazy;
use poly_commitment::{commitment::CommitmentCurve, ipa::SRS, SRS as _};
use rand::{rngs::OsRng, Rng, RngCore};
use rayon::prelude::*;
use saffron::{
    blob::FieldBlob,
    diff::{self, Diff},
};
use std::{fs::File, io::Read};
use tracing::info;

type VestaFqSponge = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;

static SRS: Lazy<SRS<Vesta>> = Lazy::new(|| {
    if let Ok(srs) = std::env::var("SRS_FILEPATH") {
        saffron::env::get_srs_from_cache(srs)
    } else {
        SRS::create(1 << 16)
    }
});

static DOMAIN: Lazy<Radix2EvaluationDomain<Fp>> =
    Lazy::new(|| Radix2EvaluationDomain::new(SRS.size()).unwrap());

static GROUP_MAP: Lazy<<Vesta as CommitmentCurve>::Map> =
    Lazy::new(<Vesta as CommitmentCurve>::Map::setup);

pub struct User {
    data: Vec<u8>,
    commitment: saffron::commitment::Commitment<Vesta>,
    n_chunks: usize,
}

impl User {
    pub fn new(data: Vec<u8>) -> Self {
        let field_elems = saffron::utils::encode_for_domain(&*DOMAIN, &data);
        let commitment = saffron::commitment::commit_to_field_elems::<Vesta, VestaFqSponge>(
            &*SRS,
            *DOMAIN,
            &field_elems,
        );

        Self {
            data,
            commitment,
            n_chunks: field_elems.len(),
        }
    }

    pub fn from_file(mut file: File) -> Self {
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();
        Self::new(data)
    }

    pub fn update(&mut self, new_data: &[u8]) -> Diff<Fp> {
        let diff = diff::Diff::<Fp>::create(&*DOMAIN, &self.data, new_data).unwrap();
        self.data = new_data.to_vec();
        self.commitment = {
            let commitment_diffs = diff
                .as_evaluations(&*DOMAIN)
                .par_iter()
                .map(|evals| SRS.commit_evaluations_non_hiding(*DOMAIN, evals))
                .collect::<Vec<_>>();
            let mut sponge = VestaFqSponge::new(Vesta::other_curve_sponge_params());
            self.commitment.update(&commitment_diffs, &mut sponge)
        };
        diff
    }
}

fn test_proof_flows(user: &User, blob: &FieldBlob<Vesta>, rng: &mut OsRng) {
    {
        info!("Checking proof of storage for initial data");
        let challenge_point = Fp::rand(&mut rand::thread_rng());

        let proof = saffron::proof::storage::storage_proof::<Vesta, VestaFqSponge>(
            &*SRS,
            &*GROUP_MAP,
            blob,
            challenge_point,
            rng,
        );

        let verifies = saffron::proof::storage::verify_storage_proof::<Vesta, VestaFqSponge>(
            &*SRS,
            &*GROUP_MAP,
            user.commitment.folded.clone(),
            challenge_point,
            &proof,
            rng,
        );
        assert!(verifies, "Proof of storage verifies");
    };

    {
        info!("Requesting a read proof for some of the initial data");
        let start = rng.gen_range(0..user.data.len() - 1);
        let end = rng.gen_range(start..user.data.len());
        let user_query = saffron::query::QueryBytes {
            start,
            len: end - start,
        };
        let query_field = user_query
            .into_query_field(DOMAIN.size(), user.n_chunks)
            .unwrap();

        // These are provided by SP
        let query_result = blob.query(*DOMAIN, &query_field);
        let proofs = saffron::proof::read::read_proof::<Vesta, _, VestaFqSponge>(
            &*SRS,
            *DOMAIN,
            &*GROUP_MAP,
            blob,
            &query_field,
            rng,
        )
        .expect("Read proof should be valid");

        // Checked by the user
        let query_evals = query_result.clone().as_evaluations(*DOMAIN);
        proofs
            .into_iter()
            .zip(query_evals)
            .for_each(|(proof, evals)| {
                let user_commitment = SRS.commit_evaluations_non_hiding(*DOMAIN, &evals);
                assert_eq!(
                    user_commitment, proof.commitment.a,
                    "Commitment to the query results matches the proof"
                );
                let verifies = saffron::proof::read::verify_read_proof::<Vesta, VestaFqSponge>(
                    &*SRS,
                    &*DOMAIN,
                    &*GROUP_MAP,
                    proof,
                    rng,
                );
                assert!(verifies, "Read proof verifies");
            });

        let result_bytes = query_field.result_decoder(&query_result);
        assert_eq!(
            result_bytes,
            &user.data[start..end],
            "Query results match the expected data"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mina_curves::pasta::Vesta;
    use rand::rngs::OsRng;
    use saffron::blob::FieldBlob;
    use std::{fs::File, path::Path};

    #[test]
    fn integration_test() {
        saffron::env::init_console_subscriber();
        let mut rng = OsRng;

        let mut user = {
            let fixtures_dir = Path::new("fixtures");
            let file = File::open(fixtures_dir.join("lorem.txt")).unwrap();
            User::from_file(file)
        };

        let mut blob = FieldBlob::<Vesta>::encode::<_, VestaFqSponge>(&*SRS, *DOMAIN, &user.data);

        assert_eq!(
            blob.commitment, user.commitment,
            "Storage provider and User share commitment to the data"
        );

        info!("Testing Proof flows for the user and storage provider on the initial data");
        test_proof_flows(&user, &blob, &mut rng);

        let og_commitment = user.commitment.clone();

        info!("Updating the data with random bytes within the allowed allocated space");
        let updated_data = {
            let len = {
                let n = saffron::utils::min_encoding_chunks(&*DOMAIN, &user.data);
                let k = saffron::utils::chunk_size_in_bytes(&*DOMAIN);
                rng.gen_range(1..=n * k)
            };
            let mut bytes = vec![0u8; len];
            OsRng.fill_bytes(&mut bytes);
            bytes
        };
        let diff = user.update(&updated_data);

        assert_ne!(
            og_commitment, user.commitment,
            "Commitment to the data changes when the data changes"
        );

        blob.update::<VestaFqSponge>(&*SRS, &*DOMAIN, diff.clone());

        assert_eq!(
            blob.commitment, user.commitment,
            "Storage provider and User share commitment to the data after the update"
        );

        info!("Testing Proof flows for the user and storage provider on the updated data");
        test_proof_flows(&user, &blob, &mut rng);
    }
}
