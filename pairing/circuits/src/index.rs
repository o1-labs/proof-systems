/*****************************************************************************************************************

This source file implements Marlin Protocol Index primitive.

*****************************************************************************************************************/

use sprs::CsMat;
use std::collections::HashMap;
use rand_core::RngCore;
use commitment_pairing::urs::URS;
use algebra::{AffineCurve, PairingEngine, curves::models::short_weierstrass_jacobian::{GroupAffine as SWJAffine}};
use oracle::rndoracle::ProofError;
use oracle::poseidon::ArithmeticSpongeParams;
pub use super::compiled::Compiled;
pub use super::gate::CircuitGate;
use evaluation_domains::EvaluationDomains;

pub trait CoordinatesCurve: AffineCurve {
    fn to_coordinates(&self) -> Option<(Self::BaseField, Self::BaseField)>;
    fn of_coordinates(x:Self::BaseField, y:Self::BaseField) -> Self;
}

impl<P: algebra::SWModelParameters> CoordinatesCurve for SWJAffine<P> {
    fn to_coordinates(&self) -> Option<(Self::BaseField, Self::BaseField)>{
        if self.infinity {
            None
        } else {
            Some((self.x, self.y))
        }
    }

    fn of_coordinates(x:Self::BaseField, y:Self::BaseField) -> Self {
        SWJAffine::<P>::new(x, y, false)
    }
}

pub enum URSValue<'a, E : PairingEngine> {
    Value(URS<E>),
    Ref(&'a URS<E>)
}

impl<'a, E : PairingEngine> URSValue<'a, E> {
    pub fn get_ref(&self) -> & URS<E> {
        match self {
            URSValue::Value(x) => &x,
            URSValue::Ref(x) => x
        }
    }
}

pub enum URSSpec <'a, 'b, E:PairingEngine>{
    Use(&'a URS<E>),
    Generate(&'b mut dyn RngCore)
}

impl<'a, E: PairingEngine> URSValue<'a, E> {
    pub fn generate<'b>(
        ds: EvaluationDomains<E::Fr>,
        rng : &'b mut dyn RngCore) -> URS<E> {
        let max_degree = *[3*ds.h.size()-1, ds.b.size()].iter().max().unwrap();

        URS::<E>::create
        (
            max_degree,
            vec!
            [
                ds.h.size()-1,
                ds.k.size()-1,
            ],
        rng )
    }

    pub fn create<'b>(ds: EvaluationDomains<E::Fr>, spec : URSSpec<'a, 'b, E>) -> URSValue<'a, E>{
        match spec {
            URSSpec::Use(x) => URSValue::Ref(x),
            URSSpec::Generate(rng) => URSValue::Value(Self::generate(ds, rng))
        }
    }
}

pub struct Index<'a, E: PairingEngine>
{
    // constraint system compilation
    pub compiled: [Compiled<E>; 3],

    // evaluation domains as multiplicative groups of roots of unity
    pub domains : EvaluationDomains<E::Fr>,

    // number of public inputs
    pub public_inputs: usize,

    // polynomial commitment keys
    pub urs: URSValue<'a, E>,

    // random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<E::Fr>,
    pub fq_sponge_params: ArithmeticSpongeParams<E::Fq>,

    // Coefficients for the curve endomorphism
    pub endo_r: E::Fr,
    pub endo_q: E::Fq,
}

pub struct MatrixValues<A> {
    pub row : A,
    pub col : A,
    pub val : A,
    pub rc : A,
}

pub struct VerifierIndex<E: PairingEngine>
{
    // constraint system compilation
    pub matrix_commitments: [MatrixValues<E::G1Affine>; 3],

    // evaluation domains as multiplicative groups of roots of unity
    pub domains : EvaluationDomains<E::Fr>,

    // number of public inputs
    pub public_inputs: usize,

    // maximal degree of the committed polynomials
    pub max_degree: usize,

    // polynomial commitment keys, trimmed
    pub urs: URS<E>,

    // random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<E::Fr>,
    pub fq_sponge_params: ArithmeticSpongeParams<E::Fq>,

    // Coefficients for the curve endomorphism
    pub endo_r: E::Fr,
    pub endo_q: E::Fq,
}

impl<'a, E: PairingEngine> Index<'a, E>
where E::G1Affine: CoordinatesCurve
{
    // this function compiles the circuit from constraints
    pub fn create<'b>
    (
        a: CsMat<E::Fr>,
        b: CsMat<E::Fr>,
        c: CsMat<E::Fr>,
        public_inputs: usize,
        fr_sponge_params: ArithmeticSpongeParams<E::Fr>,
        fq_sponge_params: ArithmeticSpongeParams<E::Fq>,
        urs : URSSpec<'a, 'b, E>
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

        let nonzero_entries : usize =
            [&a, &b, &c].iter().map(|x| x.nnz()).max()
            .map_or(Err(ProofError::RuntimeEnv), |s| Ok(s))?;

        let domains = EvaluationDomains::create(
            a.shape().0,
            public_inputs,
            nonzero_entries)
            .map_or(Err(ProofError::EvaluationGroup), |s| Ok(s))?;

        let urs = URSValue::create(domains, urs);

        let endo_q : E::Fq = oracle::marlin_sponge::endo_coefficient();
        let endo_r = {
            let potential_endo_r : E::Fr = oracle::marlin_sponge::endo_coefficient();
            let t = E::G1Affine::prime_subgroup_generator();
            let (x, y) = t.to_coordinates().unwrap();
            let phi_t = E::G1Affine::of_coordinates(x * &endo_q, y);
            if t.mul(potential_endo_r) == phi_t.into() {
                potential_endo_r
            } else {
                potential_endo_r * &potential_endo_r
            }
        };

        Ok(Index::<E>
        {
            compiled:
            [
                Compiled::<E>::compile(urs.get_ref(), domains.h, domains.k, domains.b, a)?,
                Compiled::<E>::compile(urs.get_ref(), domains.h, domains.k, domains.b, b)?,
                Compiled::<E>::compile(urs.get_ref(), domains.h, domains.k, domains.b, c)?,
            ],
            fr_sponge_params,
            fq_sponge_params,
            public_inputs,
            domains,
            urs,
            endo_q,
            endo_r
        })
    }

}

impl<'a, E: PairingEngine> Index<'a, E>
{
    fn matrix_values(c : &Compiled<E>) -> MatrixValues<E::G1Affine> {
        MatrixValues {
            row: c.row_comm,
            col: c.col_comm,
            val: c.val_comm,
            rc: c.rc_comm,
        }
    }

    pub fn verifier_index(&self) -> VerifierIndex<E> {
        let [ a, b, c ] = & self.compiled;

        let max_degree =  self.urs.get_ref().max_degree();
        let mut hn : HashMap<usize, E::G2Affine> = HashMap::new();
        for i in
            [
                self.domains.h.size()-1,
                self.domains.k.size()-1,
            ].iter() {
                let i = max_degree - i;
                hn.insert(i, self.urs.get_ref().hn.get(&i).unwrap().clone());
        }

        let urs = {
            let gp = (0..self.domains.x.size()).map(|i| self.urs.get_ref().gp[i]).collect();
            URS::<E> {
                gp,
                hn,
                hx: self.urs.get_ref().hx,
                prf: self.urs.get_ref().prf,
                depth: self.urs.get_ref().max_degree(),
            }
        };

        VerifierIndex {
            matrix_commitments : [ Self::matrix_values(a), Self::matrix_values(b), Self::matrix_values(c) ],
            domains: self.domains,
            max_degree,
            public_inputs: self.public_inputs,
            fr_sponge_params: self.fr_sponge_params.clone(),
            fq_sponge_params: self.fq_sponge_params.clone(),
            urs,
            endo_q: self.endo_q,
            endo_r: self.endo_r,
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
        let mut gates = vec![CircuitGate::<E::Fr>::zero(); self.domains.h.size()];
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
