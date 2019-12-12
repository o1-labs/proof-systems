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
pub use super::witness::Witness;

pub struct Index<E: PairingEngine>
{
    // constraint system compilation
    pub compiled: [Compiled<E>; 3],

    // evaluation domains as multiplicative groups of roots of unity
    pub h_group: EvaluationDomain<E::Fr>,
    pub k_group: EvaluationDomain<E::Fr>,

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
        oracles: ArithmeticSpongeParams<E::Fr>,
        rng: &mut dyn RngCore
    ) -> Result<Self, ProofError>
    {
        if a.shape() != b.shape() || a.shape() != c.shape() || a.shape().0 != a.shape().1 {return Err(ProofError::ConstraintInconsist)}

        // compute the evaluation domains
        match
        (
            EvaluationDomain::<E::Fr>::new(a.shape().0),
            EvaluationDomain::<E::Fr>::new([&a, &b, &c].iter().map(|x| x.nnz()).max().unwrap())
        )
        {
            (Some(h_group), Some(k_group)) =>
            {
                // maximal degree of the committed polynomials
                let max_degree = *[3*h_group.size, 6*k_group.size].iter().max().unwrap() as usize;

                // compute public setup
                let urs = URS::<E>::create(max_degree, rng);

                // compile the constraints
                Ok(Index::<E>
                {
                    compiled:
                    [
                        Compiled::<E>::compile(&urs, h_group, k_group, a)?,
                        Compiled::<E>::compile(&urs, h_group, k_group, b)?,
                        Compiled::<E>::compile(&urs, h_group, k_group, c)?,
                    ],
                    oracle_params: oracles,
                    max_degree: max_degree,
                    h_group: h_group,
                    k_group: k_group,
                    urs: urs,
                })
            }
            (_,_) => Err(ProofError::EvaluationGroup)
        }
    }

    // This function verifies the consistency of the wire assignements (witness) against the constraints
    //     witness: wire assignement witness
    //     RETURN: verification status
    pub fn verify
    (
        &self,
        witness: &Witness<E::Fr>
    ) -> bool
    {
        if self.compiled[0].constraints.shape().1 != witness.0.len() {return false}

        for (a, (b, c)) in
            self.compiled[0].constraints.outer_iterator().zip(
                self.compiled[1].constraints.outer_iterator().zip(
                    self.compiled[2].constraints.outer_iterator()))
        {
            let mut gate = CircuitGate::<E::Fr>::zero();
            for col in a.iter()
            {
                gate.wire[0] += &(*col.1 * &witness.0[col.0]);
            }
            for col in b.iter()
            {
                gate.wire[1] += &(*col.1 * &witness.0[col.0]);
            }
            for col in c.iter()
            {
                gate.wire[2] += &(*col.1 * &witness.0[col.0]);
            }
            if gate.wire[0] * &gate.wire[1] != gate.wire[2] {return false}
        }
        true
    }
}