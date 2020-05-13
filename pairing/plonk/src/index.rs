/*****************************************************************************************************************

This source file implements Plonk Protocol Index primitive.

*****************************************************************************************************************/

use rand_core::RngCore;
use commitment_pairing::urs::URS;
use algebra::{Field, AffineCurve, PairingEngine, curves::models::short_weierstrass_jacobian::{GroupAffine as SWJAffine}};
use ff_fft::{Evaluations, EvaluationDomain};
use oracle::rndoracle::ProofError;
use oracle::poseidon::ArithmeticSpongeParams;
use plonk_circuits::{gate::CircuitGate, witness::Witness, domains::EvaluationDomains};

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
        let max_degree = 3*ds.h.size()-1;

        URS::<E>::create
        (
            max_degree,
            vec!
            [
                ds.h.size()-1,
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
    // evaluation domains as multiplicative groups of roots of unity
    pub domains : EvaluationDomains<E::Fr>,

    pub gates:  Vec<CircuitGate>,          // circuit gates

    pub sigma:  [Evaluations<E::Fr>; 3],   // permutation polynomial array
    pub sid:    Evaluations<E::Fr>,        // SID polynomial

    pub ql:     Evaluations<E::Fr>,        // left input wire polynomial
    pub qr:     Evaluations<E::Fr>,        // right input wire polynomial
    pub qo:     Evaluations<E::Fr>,        // output wire polynomial
    pub qm:     Evaluations<E::Fr>,        // multiplication polynomial
    pub qc:     Evaluations<E::Fr>,        // constant wire polynomial

    // polynomial commitment keys
    pub urs: URSValue<'a, E>,

    // random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<E::Fr>,
    pub fq_sponge_params: ArithmeticSpongeParams<E::Fq>,

    // Coefficients for the curve endomorphism
    pub endo_r: E::Fr,
    pub endo_q: E::Fq,
}

pub struct VerifierIndex<E: PairingEngine>
{
    pub h_group: EvaluationDomain<E::Fr>,

    // polynomial commitment keys, trimmed
    pub urs: URS<E>,

    // random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<E::Fr>,
    pub fq_sponge_params: ArithmeticSpongeParams<E::Fq>,

    // Coefficients for the curve endomorphism
    pub endo_r: E::Fr,
    pub endo_q: E::Fq,
}

pub fn endos<E:PairingEngine>() -> (E::Fq, E::Fr) where E::G1Affine : CoordinatesCurve {
    let endo_q : E::Fq = oracle::sponge::endo_coefficient();
    let endo_r = {
        let potential_endo_r : E::Fr = oracle::sponge::endo_coefficient();
        let t = E::G1Affine::prime_subgroup_generator();
        let (x, y) = t.to_coordinates().unwrap();
        let phi_t = E::G1Affine::of_coordinates(x * &endo_q, y);
        if t.mul(potential_endo_r) == phi_t.into() {
            potential_endo_r
        } else {
            potential_endo_r * &potential_endo_r
        }
    };
    (endo_q, endo_r)
}

impl<'a, E: PairingEngine> Index<'a, E>
where E::G1Affine: CoordinatesCurve
{
    // this function compiles the circuit from constraints
    pub fn create<'b>
    (
        _fr_sponge_params: ArithmeticSpongeParams<E::Fr>,
        _fq_sponge_params: ArithmeticSpongeParams<E::Fq>,
        _urs : URSSpec<'a, 'b, E>
    ) -> Result<Self, ProofError>
    {
        Err(ProofError::ProofCreation)
    }
}

impl<'a, E: PairingEngine> Index<'a, E>
{
    pub fn verifier_index(&self) -> Result<VerifierIndex<E>, ProofError> {
        Err(ProofError::ProofCreation)
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
        for i in 0..self.sid.evals.len()-2
        {
            if
            !(
                self.ql.evals[i] * &witness[self.gates[i].l] +
                &(self.qr.evals[i] * &witness[self.gates[i].r]) +
                &(self.qo.evals[i] * &witness[self.gates[i].o]) +
                &(self.qm.evals[i] * &witness[self.gates[i].l] * &witness[self.gates[i].r]) +
                &self.qc.evals[i]
            ).is_zero()
            {return false}
        }
        true
    }
}
