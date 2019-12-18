/*****************************************************************************************************************

This source file implements Marlin Protocol Index primitive.

*****************************************************************************************************************/

use sprs::CsMat;
use rand_core::RngCore;
use commitment::urs::URS;
use algebra::PairingEngine;
use ff_fft::EvaluationDomain;
use oracle::rndoracle::ProofError;
use oracle::poseidon::ArithmeticSpongeParams;
pub use super::compiled::Compiled;
pub use super::gate::CircuitGate;

pub struct Index<E: PairingEngine>
{
    // constraint system compilation
    pub compiled: [Compiled<E>; 3],

    // evaluation domains as multiplicative groups of roots of unity
    pub h_group: EvaluationDomain<E::Fr>,
    pub k_group: EvaluationDomain<E::Fr>,
    pub b_group: EvaluationDomain<E::Fr>,
    pub x_group: EvaluationDomain<E::Fr>,

    // number of public inputs
    pub public_inputs: usize,

    // maximal degree of the committed polynomials
    pub max_degree: usize,

    // polynomial commitment keys
    pub urs: URS<E>,

    // random oracle argument parameters
    pub oracle_params: ArithmeticSpongeParams<E::Fr>,
}

impl<E: PairingEngine> Index<E>
{
    // this function compiles the circuit from constraints
    pub fn create
    (
        a: CsMat<E::Fr>,
        b: CsMat<E::Fr>,
        c: CsMat<E::Fr>,
        public_inputs: usize,
        oracle_params: ArithmeticSpongeParams<E::Fr>,
        rng: &mut dyn RngCore
    ) -> Result<Self, ProofError>
    {
        if a.shape() != b.shape() ||
            a.shape() != c.shape() ||
            a.shape().0 != a.shape().1 ||
            public_inputs == a.shape().0 ||
            public_inputs == 0
        {
            return Err(ProofError::ConstraintInconsist)
        }

        // compute the evaluation domains
        let h_group_size = EvaluationDomain::<E::Fr>::compute_size_of_domain(a.shape().0).unwrap();
        let x_group_size = EvaluationDomain::<E::Fr>::compute_size_of_domain(public_inputs).unwrap();
        let k_group_size = EvaluationDomain::<E::Fr>::compute_size_of_domain
            ([&a, &b, &c].iter().map(|x| x.nnz()).max().unwrap()).unwrap(); // TODO: handle errors properly

        match
        (
            EvaluationDomain::<E::Fr>::new(h_group_size),
            EvaluationDomain::<E::Fr>::new(k_group_size),
            EvaluationDomain::<E::Fr>::new(k_group_size * 6 - 6),
            EvaluationDomain::<E::Fr>::new(x_group_size),
        )
        {
            (Some(h_group), Some(k_group), Some(b_group), Some(x_group)) =>
            {
                // maximal degree of the committed polynomials
                let max_degree = *[3*h_group.size-1, 6*k_group.size-6].iter().max().unwrap() as usize;
     
                // compute public setup
                let urs = URS::<E>::create(max_degree, rng);

                // compile the constraints
                Ok(Index::<E>
                {
                    compiled:
                    [
                        Compiled::<E>::compile(&urs, h_group, k_group, b_group, a)?,
                        Compiled::<E>::compile(&urs, h_group, k_group, b_group, b)?,
                        Compiled::<E>::compile(&urs, h_group, k_group, b_group, c)?,
                    ],
                    oracle_params,
                    public_inputs,
                    max_degree,
                    h_group,
                    k_group,
                    b_group,
                    x_group,
                    urs,
                })
            }
            (_,_,_,_) => Err(ProofError::EvaluationGroup)
        }
    }

    // This function verifies the consistency of the wire assignements (witness) against the constraints
    //     witness: wire assignement witness
    //     RETURN: verification status
    pub fn verify
    (
        &self,
        witness: &Vec<E::Fr>
    ) -> bool
    {
        if self.compiled[0].constraints.shape().1 != witness.len() {return false}

        for (a, (b, c)) in
            self.compiled[0].constraints.outer_iterator().zip(
                self.compiled[1].constraints.outer_iterator().zip(
                    self.compiled[2].constraints.outer_iterator()))
        {
            let mut gate = CircuitGate::<E::Fr>::zero();
            for col in a.iter()
            {
                gate.wire[0] += &(*col.1 * &witness[col.0]);
            }
            for col in b.iter()
            {
                gate.wire[1] += &(*col.1 * &witness[col.0]);
            }
            for col in c.iter()
            {
                gate.wire[2] += &(*col.1 * &witness[col.0]);
            }
            if gate.wire[0] * &gate.wire[1] != gate.wire[2] {return false}
        }
        true
    }
}