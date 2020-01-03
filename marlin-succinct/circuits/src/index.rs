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
use std::collections::HashMap;

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
    pub fr_sponge_params: ArithmeticSpongeParams<E::Fr>,
    pub fq_sponge_params: ArithmeticSpongeParams<E::Fq>,
}

pub struct MatrixValues<A> {
    pub row : A,
    pub col : A,
    pub val : A,
}

pub struct VerifierIndex<E: PairingEngine>
{
    // constraint system compilation
    pub matrix_commitments: [MatrixValues<E::G1Affine>; 3],

    // evaluation domains as multiplicative groups of roots of unity
    pub h_group: EvaluationDomain<E::Fr>,
    pub k_group: EvaluationDomain<E::Fr>,
    pub x_group: EvaluationDomain<E::Fr>,

    // number of public inputs
    pub public_inputs: usize,

    // maximal degree of the committed polynomials
    pub max_degree: usize,

    // polynomial commitment keys, trimmed
    pub urs: URS<E>,

    // random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<E::Fr>,
    pub fq_sponge_params: ArithmeticSpongeParams<E::Fq>,
}

impl<E: PairingEngine> Index<E>
{
    fn matrix_values(c : &Compiled<E>) -> MatrixValues<E::G1Affine> {
        MatrixValues {
            row: c.row_comm,
            col: c.col_comm,
            val: c.val_comm,
        }
    }

    pub fn verifier_index(&self) -> VerifierIndex<E> {
        let [ a, b, c ] = & self.compiled;

        let h_to_x_ratio = self.h_group.size() / self.x_group.size();

        let urs = {
            let gp = (0..self.x_group.size()).map(|i| self.urs.gp[i * h_to_x_ratio]).collect();
            URS::<E> {
                gp,
                // TODO: We just need (beta^{N - (h_group.size() - 1)}) and (beta^{N - (k_group.size() - 1)})
                hn : HashMap::new(),
                hx: self.urs.hx,
                prf: self.urs.prf
            }
        };

        VerifierIndex {
            matrix_commitments : [ Self::matrix_values(a), Self::matrix_values(b), Self::matrix_values(c) ],
            x_group: self.x_group,
            h_group: self.h_group,
            k_group: self.k_group,
            max_degree: self.max_degree,
            public_inputs: self.public_inputs,
            fr_sponge_params: self.fr_sponge_params.clone(),
            fq_sponge_params: self.fq_sponge_params.clone(),
            urs
        }
    }

    // this function compiles the circuit from constraints
    pub fn create
    (
        a: CsMat<E::Fr>,
        b: CsMat<E::Fr>,
        c: CsMat<E::Fr>,
        public_inputs: usize,
        fr_sponge_params: ArithmeticSpongeParams<E::Fr>,
        fq_sponge_params: ArithmeticSpongeParams<E::Fq>,
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
        let h_group_size = 
            EvaluationDomain::<E::Fr>::compute_size_of_domain(a.shape().0)
            .map_or(Err(ProofError::EvaluationGroup), |s| Ok(s))?;
        let x_group_size =
            EvaluationDomain::<E::Fr>::compute_size_of_domain(public_inputs)
            .map_or(Err(ProofError::EvaluationGroup), |s| Ok(s))?;
        let k_group_size =
            EvaluationDomain::<E::Fr>::compute_size_of_domain
            ([&a, &b, &c].iter().map(|x| x.nnz()).max()
            .map_or(Err(ProofError::RuntimeEnv), |s| Ok(s))?)
            .map_or(Err(ProofError::EvaluationGroup), |s| Ok(s))?;

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
                let max_degree = *[3*h_group.size()-1, b_group.size()].iter().max()
                    .map_or(Err(ProofError::RuntimeEnv), |s| Ok(s))?;
     
                // compute public setup
                let urs = URS::<E>::create
                (
                    max_degree,
                    vec!
                    [
                        h_group.size(),
                        h_group.size() - x_group.size(),
                        h_group.size()*2-2,
                        h_group.size()-1,
                        k_group.size()*6-6,
                        k_group.size()-1,
                        k_group.size()
                    ],
                    rng
                );

                // compile the constraints
                Ok(Index::<E>
                {
                    compiled:
                    [
                        Compiled::<E>::compile(&urs, h_group, k_group, b_group, a)?,
                        Compiled::<E>::compile(&urs, h_group, k_group, b_group, b)?,
                        Compiled::<E>::compile(&urs, h_group, k_group, b_group, c)?,
                    ],
                    fr_sponge_params,
                    fq_sponge_params,
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
        let mut gates = vec![CircuitGate::<E::Fr>::zero(); self.h_group.size()];
        for i in 0..3
        {
            for val in self.compiled[i].constraints.iter()
            {
                gates[(val.1).0].wire[i] += &(witness[(val.1).1] * &val.0)
            }
        }
        for gate in gates.iter()
        {
            if gate.wire[0] * &gate.wire[1] != gate.wire[2] {return false}
        }
        true
    }
}
