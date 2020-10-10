/*****************************************************************************************************************

This source file tests polynomial commitments, batched openings and
verification of a batch of batched opening proofs of polynomial commitments
with varying URS length

*****************************************************************************************************************/

use algebra::{bn_382::{g::{Affine, Bn_382GParameters}, Fp}, UniformRand, AffineCurve};
use commitment_dlog::{srs::SRS, commitment::{CommitmentCurve, OpeningProof, PolyComm}};
use oracle::utils::PolyUtils;

use oracle::FqSponge;
use oracle::sponge::{DefaultFqSponge};
use oracle::poseidon::{PlonkSpongeConstants as SC};

use std::time::{Instant, Duration};
use ff_fft::DensePolynomial;
use colored::Colorize;
use rand_core::OsRng;
use rand::Rng;
use groupmap::GroupMap;


type Fr = <Affine as AffineCurve>::ScalarField;

#[test]
fn heterogeneous_batch_commitment_test()
where <Fp as std::str::FromStr>::Err : std::fmt::Debug
{
    let max_rounds = 10;
    let max_size = 1 << max_rounds;
    let srs = SRS::<Affine>::create(max_size, 0, 0);

    let polys_per_opening = 3;
    let batch_size = 5;

    let group_map = <Affine as CommitmentCurve>::Map::setup();
    let rng = &mut OsRng;
    let mut random = rand::thread_rng();

// code before new approach
    let mut proofs = Vec::
        <(
            DefaultFqSponge<Bn_382GParameters, SC>,
            Vec<Fr>,
            Fr,
            Fr,
            Vec<(&PolyComm<Affine>, &Vec<Vec<Fr>>, Option<usize>)>,
            &OpeningProof<Affine>,
        )>::new();

// structure of the vector       
    pub struct ProofCollection<'a> {
        proofs_new: Vec<(
            DefaultFqSponge<Bn_382GParameters, SC>,
            Vec<Fr>,
            Fr,
            Fr,
            Vec<(&'a PolyComm<Affine>, &'a Vec<Vec<Fr>>, Option<usize>)>,
            &'a OpeningProof<Affine>,
        )>
    }
   
    // construct new for the structure
    impl<'a> ProofCollection<'a> {
        pub fn new() -> Self {
            ProofCollection { proofs_new: Vec::
                <(
                    DefaultFqSponge<Bn_382GParameters, SC>,
                    Vec<Fr>,
                    Fr,
                    Fr,
                    Vec<(&PolyComm<Affine>, &Vec<Vec<Fr>>, Option<usize>)>,
                    &OpeningProof<Affine>,
                )>::new() }
            }

   

// given value, insert reference into the vector
    pub fn insert(&mut self, proof_collection_values: &'a  ProofCollectionValues) {

        let evals = proof_collection_values.a.iter().map
        (
            |a| proof_collection_values.x.into_iter().map(|xx| a.eval(*xx, proof_collection_values.size)).collect::<Vec<_>>()
        ).collect::<Vec<_>>();
        
        let evals_temp = (0..proof_collection_values.a.len()).map
        (
            |j|
            (
                let tempvec: Vec<_> = evals[j].iter().map(|evl| format!("{}Foo", evl)).cloned().collect();
                tempvec
            )

        ).collect::<Vec<_>>();

        

        let inner_vector = (0..proof_collection_values.a.len()).map
        (
            |j|
            (
                &proof_collection_values.comm[j],
                &evals[j],
                if j%2==0 {Some(proof_collection_values.a[j].coeffs.len())} else {None})
            ).collect::<Vec<_>>();
        let final_tuple = (
            proof_collection_values.sponge.clone(),
            proof_collection_values.x.clone(),
            proof_collection_values.polymask,
            proof_collection_values.evalmask,
            inner_vector,
            proof_collection_values.proof
        );

        self.proofs_new.push(final_tuple);
            }
    }

        //todo split pcv into with and without lifetimes


    //structure of vector of values (no references)

    pub struct ProofCollectionValues {
            sponge: DefaultFqSponge<Bn_382GParameters, SC>,
            x: Vec<Fr>,
            polymask: Fr,
            evalmask: Fr,
            comm: Vec<PolyComm<Affine>>,
            a: Vec<DensePolynomial<Fr>>,
            size: usize,
            proof: OpeningProof<Affine>       
    }

    let mut pcv_vector : Vec<ProofCollectionValues> = Vec::new();
    let mut my_pc_vector = ProofCollection::new();
    

    for i in 0..batch_size {
        let rounds = max_rounds - i;
        let size = 1 << rounds;
        // TODO: Produce opening proofs with (max_rounds - i) many rounds
        let srsnew = SRS {g : srs.g[0..size].to_vec(), lgr_comm : srs.lgr_comm.clone(),..srs};
        let a = (0..polys_per_opening).map(|_| DensePolynomial::<Fr>::rand(size,rng)).collect::<Vec<_>>();
        let comm  = (0..a.len()).map
            (
                |j|
                {
                    if j%2==0 {srsnew.commit(&a[i].clone(), Some(a[i].coeffs.len()))}
                    else {srsnew.commit(&a[i].clone(), None)}
                }
            ).collect::<Vec<_>>();

        let x = (0..7).map(|_| Fr::rand(rng)).collect::<Vec<Fr>>();
        let polymask = Fr::rand(rng);
        let evalmask = Fr::rand(rng);
        let evals = a.iter().map
        (
            |a| x.iter().map(|xx| a.eval(*xx, size)).collect::<Vec<_>>()
        ).collect::<Vec<_>>();

        let sponge = DefaultFqSponge::<Bn_382GParameters, SC>::new(oracle::bn_382::fp::params());
        let proof = srsnew.open::<DefaultFqSponge<Bn_382GParameters, SC>>
        (
            rounds,
            &group_map,
            (0..a.len()).map
            (
                |i| (&a[i], if i%2==0 {Some(a[i].coeffs.len())} else {None})
            ).collect::<Vec<_>>(),
            &x.clone(),
            polymask,
            evalmask,
            sponge.clone(),
            rng,
        );

        let mut pcv = ProofCollectionValues {
            sponge: sponge.clone(),
            x: x,
            polymask: polymask,
            evalmask: evalmask,
            comm: comm,
            a: a,
            size: size,
            proof: proof,
        };

        pcv_vector.push(pcv);

    }

    pcv_vector.iter().for_each(|value| my_pc_vector.insert(&value));
    





    assert!(srs.verify::<DefaultFqSponge<Bn_382GParameters, SC>>
        (
            &group_map,
            &mut my_pc_vector.proofs_new,
            rng
        ));
}
