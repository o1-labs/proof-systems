/*****************************************************************************************************************

This source file implements Plonk Protocol Index primitive.

*****************************************************************************************************************/

use algebra::{
    curves::models::short_weierstrass_jacobian::GroupAffine as SWJAffine, AffineCurve, One,
    PairingEngine, Zero,
};
use commitment_pairing::urs::URS;
use ff_fft::{DensePolynomial, EvaluationDomain, Radix2EvaluationDomain as D};
use oracle::poseidon::ArithmeticSpongeParams;
use oracle::rndoracle::ProofError;
use plonk_circuits::constraints::ConstraintSystem;
use rand_core::RngCore;

pub trait CoordinatesCurve: AffineCurve {
    fn to_coordinates(&self) -> Option<(Self::BaseField, Self::BaseField)>;
    fn of_coordinates(x: Self::BaseField, y: Self::BaseField) -> Self;
}

impl<P: algebra::SWModelParameters> CoordinatesCurve for SWJAffine<P> {
    fn to_coordinates(&self) -> Option<(Self::BaseField, Self::BaseField)> {
        if self.infinity {
            None
        } else {
            Some((self.x, self.y))
        }
    }

    fn of_coordinates(x: Self::BaseField, y: Self::BaseField) -> Self {
        SWJAffine::<P>::new(x, y, false)
    }
}

pub enum URSValue<'a, E: PairingEngine> {
    Value(URS<E>),
    Ref(&'a URS<E>),
}

impl<'a, E: PairingEngine> URSValue<'a, E> {
    pub fn get_ref(&self) -> &URS<E> {
        match self {
            URSValue::Value(x) => &x,
            URSValue::Ref(x) => x,
        }
    }
}

pub enum URSSpec<'a, 'b, E: PairingEngine> {
    Use(&'a URS<E>),
    Generate(&'b mut dyn RngCore),
}

impl<'a, E: PairingEngine> URSValue<'a, E> {
    pub fn generate<'b>(degree: usize, rng: &'b mut dyn RngCore) -> URS<E> {
        URS::<E>::create(degree, vec![], rng)
    }

    pub fn create<'b>(degree: usize, spec: URSSpec<'a, 'b, E>) -> URSValue<'a, E> {
        match spec {
            URSSpec::Use(x) => URSValue::Ref(x),
            URSSpec::Generate(rng) => URSValue::Value(Self::generate(degree, rng)),
        }
    }
}

pub struct Index<'a, E: PairingEngine> {
    // constraints as Lagrange-based polynomials
    pub cs: ConstraintSystem<E::Fr>,

    // polynomial commitment keys
    pub urs: URSValue<'a, E>,

    // random oracle argument parameters
    pub fq_sponge_params: ArithmeticSpongeParams<E::Fq>,

    // Coefficients for the curve endomorphism
    pub endo_r: E::Fr,
    pub endo_q: E::Fq,
}

pub struct VerifierIndex<E: PairingEngine> {
    pub domain: D<E::Fr>, // evaluation domain

    // index polynomial commitments
    pub sigma_comm: [E::G1Affine; 3], // permutation commitment array
    pub sid_comm: E::G1Affine,        // SID commitment
    pub ql_comm: E::G1Affine,         // left input wire commitment
    pub qr_comm: E::G1Affine,         // right input wire commitment
    pub qo_comm: E::G1Affine,         // output wire commitment
    pub qm_comm: E::G1Affine,         // multiplication commitment
    pub qc_comm: E::G1Affine,         // constant wire commitment

    pub r: E::Fr, // coordinate shift for right wires
    pub o: E::Fr, // coordinate shift for output wires

    // polynomial commitment keys, trimmed
    pub urs: URS<E>,

    // random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<E::Fr>,
    pub fq_sponge_params: ArithmeticSpongeParams<E::Fq>,

    // Coefficients for the curve endomorphism
    pub endo_r: E::Fr,
    pub endo_q: E::Fq,
}

pub fn endos<E: PairingEngine>() -> (E::Fq, E::Fr)
where
    E::G1Affine: CoordinatesCurve,
{
    let endo_q: E::Fq = oracle::sponge::endo_coefficient();
    let endo_r = {
        let potential_endo_r: E::Fr = oracle::sponge::endo_coefficient();
        let t = E::G1Affine::prime_subgroup_generator();
        let (x, y) = t.to_coordinates().unwrap();
        let phi_t = E::G1Affine::of_coordinates(x * &endo_q, y);
        if t.mul(potential_endo_r) == phi_t.into_projective() {
            potential_endo_r
        } else {
            potential_endo_r * &potential_endo_r
        }
    };
    (endo_q, endo_r)
}

impl<'a, E: PairingEngine> Index<'a, E>
where
    E::G1Affine: CoordinatesCurve,
{
    // this function compiles the circuit from constraints
    pub fn create<'b>(
        cs: ConstraintSystem<E::Fr>,
        fq_sponge_params: ArithmeticSpongeParams<E::Fq>,
        urs: URSSpec<'a, 'b, E>,
    ) -> Self {
        let urs = URSValue::create(cs.domain.d1.size() + 3, urs);
        let (endo_q, endo_r) = endos::<E>();

        Index {
            fq_sponge_params,
            endo_q,
            endo_r,
            urs,
            cs,
        }
    }

    pub fn verifier_index(&self) -> Result<VerifierIndex<E>, ProofError> {
        let urs = self.urs.get_ref().clone();
        Ok(VerifierIndex {
            domain: self.cs.domain.d1,

            sid_comm: urs.commit(&DensePolynomial::from_coefficients_slice(&[
                E::Fr::zero(),
                E::Fr::one(),
            ]))?,
            sigma_comm: [
                urs.commit(&self.cs.sigmam[0])?,
                urs.commit(&self.cs.sigmam[1])?,
                urs.commit(&self.cs.sigmam[2])?,
            ],
            ql_comm: urs.commit(&self.cs.qlm)?,
            qr_comm: urs.commit(&self.cs.qrm)?,
            qo_comm: urs.commit(&self.cs.qom)?,
            qm_comm: urs.commit(&self.cs.qmm)?,
            qc_comm: urs.commit(&self.cs.qc)?,

            fr_sponge_params: self.cs.fr_sponge_params.clone(),
            fq_sponge_params: self.fq_sponge_params.clone(),
            endo_q: self.endo_q,
            endo_r: self.endo_r,
            urs,
            r: self.cs.r,
            o: self.cs.o,
        })
    }
}
