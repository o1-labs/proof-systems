/*****************************************************************************************************************

This source file implements Plonk Protocol Index primitive.

*****************************************************************************************************************/

use rand_core::RngCore;
use commitment_pairing::urs::URS;
use ff_fft::{DensePolynomial, EvaluationDomain, Evaluations};
use algebra::{Field, AffineCurve, PairingEngine, curves::models::short_weierstrass_jacobian::{GroupAffine as SWJAffine}};
use oracle::rndoracle::ProofError;
use oracle::poseidon::ArithmeticSpongeParams;
use plonk_circuits::constraints::ConstraintSystem;

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

    // index polynomials over the monomial base
    pub sigma:  [DensePolynomial<E::Fr>; 3],   // permutation polynomial array
    pub sid:    DensePolynomial<E::Fr>,        // SID polynomial
    pub ql:     DensePolynomial<E::Fr>,        // left input wire polynomial
    pub qr:     DensePolynomial<E::Fr>,        // right input wire polynomial
    pub qo:     DensePolynomial<E::Fr>,        // output wire polynomial
    pub qm:     DensePolynomial<E::Fr>,        // multiplication polynomial
    pub qc:     DensePolynomial<E::Fr>,        // constant wire polynomial
    pub l0:     DensePolynomial<E::Fr>,        // 1-st Lagrange base polynomial

    // index polynomial commitments
    pub sigma_comm:  [E::G1Affine; 3],   // permutation commitment array
    pub sid_comm:    E::G1Affine,        // SID commitment
    pub ql_comm:     E::G1Affine,        // left input wire commitment
    pub qr_comm:     E::G1Affine,        // right input wire commitment
    pub qo_comm:     E::G1Affine,        // output wire commitment
    pub qm_comm:     E::G1Affine,        // multiplication commitment
    pub qc_comm:     E::G1Affine,        // constant wire commitment

    // random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<E::Fr>,
    pub fq_sponge_params: ArithmeticSpongeParams<E::Fq>,

    // Coefficients for the curve endomorphism
    pub endo_r: E::Fr,
    pub endo_q: E::Fq,
}

pub struct VerifierIndex<E: PairingEngine>
{
    pub domain: EvaluationDomain<E::Fr>, // evaluation domain

    pub l0:     DensePolynomial<E::Fr>,  // 1-st Lagrange base polynomial

    // index polynomial commitments
    pub sigma_comm:  [E::G1Affine; 3],   // permutation commitment array
    pub sid_comm:    E::G1Affine,        // SID commitment
    pub ql_comm:     E::G1Affine,        // left input wire commitment
    pub qr_comm:     E::G1Affine,        // right input wire commitment
    pub qo_comm:     E::G1Affine,        // output wire commitment
    pub qm_comm:     E::G1Affine,        // multiplication commitment
    pub qc_comm:     E::G1Affine,        // constant wire commitment

    pub r: E::Fr,   // coordinate shift for right wires
    pub o: E::Fr,   // coordinate shift for output wires

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
        cs: ConstraintSystem<E::Fr>,
        fr_sponge_params: ArithmeticSpongeParams<E::Fr>,
        fq_sponge_params: ArithmeticSpongeParams<E::Fq>,
        urs : URSSpec<'a, 'b, E>
    ) -> Result<Self, ProofError>
    {
        let urs = URSValue::create(cs.domain.size()+3, urs);
        let (endo_q, endo_r) = endos::<E>();

        let sigma = [cs.sigma[0].interpolate_by_ref(), cs.sigma[1].interpolate_by_ref(), cs.sigma[2].interpolate_by_ref()];
        let sid = DensePolynomial::from_coefficients_slice(&[E::Fr::zero(), E::Fr::one()]);
        let ql = cs.ql.interpolate_by_ref();
        let qr = cs.qr.interpolate_by_ref();
        let qo = cs.qo.interpolate_by_ref();
        let qm = cs.qm.interpolate_by_ref();
        let qc = cs.qc.interpolate_by_ref();
    
        Ok(Index
        {
            sigma_comm: [urs.get_ref().commit(&sigma[0])?, urs.get_ref().commit(&sigma[1])?, urs.get_ref().commit(&sigma[2])?],
            sid_comm: urs.get_ref().commit(&DensePolynomial::from_coefficients_slice(&[E::Fr::zero(), E::Fr::one()]))?,
            ql_comm: urs.get_ref().commit(&ql)?,
            qr_comm: urs.get_ref().commit(&qr)?,
            qo_comm: urs.get_ref().commit(&qo)?,
            qm_comm: urs.get_ref().commit(&qm)?,
            qc_comm: urs.get_ref().commit(&qc)?,

            sigma,
            sid,
            ql,
            qr,
            qo,
            qm,
            qc,
            
            l0: Evaluations::<E::Fr>::from_vec_and_domain(vec![E::Fr::one()], cs.domain).interpolate(),
            fr_sponge_params,
            fq_sponge_params,
            endo_q,
            endo_r,
            urs,
            cs,
        })
    }

    pub fn verifier_index(&self) -> VerifierIndex<E>
    {
        VerifierIndex
        {
            domain: self.cs.domain,
            l0: self.l0.clone(),
            sigma_comm: self.sigma_comm,
            sid_comm: self.sid_comm,
            ql_comm: self.ql_comm,
            qr_comm: self.qr_comm,
            qo_comm: self.qo_comm,
            qm_comm: self.qm_comm,
            qc_comm: self.qc_comm,
            fr_sponge_params: self.fr_sponge_params.clone(),
            fq_sponge_params: self.fq_sponge_params.clone(),
            endo_q: self.endo_q,
            endo_r: self.endo_r,
            urs: self.urs.get_ref().clone(),
            r: self.cs.r,
            o: self.cs.o,
        }
    }
}
