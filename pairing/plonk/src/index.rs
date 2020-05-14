/*****************************************************************************************************************

This source file implements Plonk Protocol Index primitive.

*****************************************************************************************************************/

use rand_core::RngCore;
use commitment_pairing::urs::URS;
use algebra::{AffineCurve, PairingEngine, curves::models::short_weierstrass_jacobian::{GroupAffine as SWJAffine}};
use ff_fft::EvaluationDomain;
use oracle::rndoracle::ProofError;
use oracle::poseidon::ArithmeticSpongeParams;
use plonk_circuits::{gate::CircuitGate, constraints::ConstraintSystem};

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
        degree: usize,
        rng : &'b mut dyn RngCore) -> URS<E> {

        URS::<E>::create
        (
            
            degree,
            vec![],
        rng )
    }

    pub fn create<'b>(degree: usize, spec : URSSpec<'a, 'b, E>) -> URSValue<'a, E>{
        match spec {
            URSSpec::Use(x) => URSValue::Ref(x),
            URSSpec::Generate(rng) => URSValue::Value(Self::generate(degree, rng))
        }
    }
}

pub struct Index<'a, E: PairingEngine>
{
    // constraints as Lagrange-based polynoms
    pub cs: ConstraintSystem<E::Fr>,

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
        gates: &[CircuitGate<E::Fr>],
        fr_sponge_params: ArithmeticSpongeParams<E::Fr>,
        fq_sponge_params: ArithmeticSpongeParams<E::Fq>,
        urs : URSSpec<'a, 'b, E>
    ) -> Result<Self, ProofError>
    {
        let cs = ConstraintSystem::<E::Fr>::create(gates).map_or(Err(ProofError::EvaluationGroup), |s| Ok(s))?;
        let urs = URSValue::create(cs.domain.size(), urs);
        let (endo_q, endo_r) = endos::<E>();

        Ok(Index
        {
            cs,
            urs,
            fr_sponge_params,
            fq_sponge_params,
            endo_q,
            endo_r
        })
    }
}

impl<'a, E: PairingEngine> Index<'a, E>
{
    pub fn verifier_index(&self) -> Result<VerifierIndex<E>, ProofError> {
        Err(ProofError::ProofCreation)
    }
}
