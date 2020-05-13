/*****************************************************************************************************************

This source file implements Plonk Protocol Index primitive.

*****************************************************************************************************************/

use commitment_dlog::{srs::SRS, commitment::{CommitmentCurve, PolyComm}};
use ff_fft::{Evaluations, EvaluationDomain};
use algebra::{Field, AffineCurve};
use oracle::rndoracle::ProofError;
use oracle::poseidon::ArithmeticSpongeParams;
use plonk_circuits::{gate::CircuitGate, witness::Witness, domains::EvaluationDomains};
use algebra::PrimeField;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

pub enum SRSValue<'a, G : CommitmentCurve> {
    Value(SRS<G>),
    Ref(&'a SRS<G>)
}

impl<'a, G : CommitmentCurve> SRSValue<'a, G> {
    pub fn get_ref(&self) -> & SRS<G> {
        match self {
            SRSValue::Value(x) => &x,
            SRSValue::Ref(x) => x
        }
    }
}

pub enum SRSSpec <'a, G: CommitmentCurve>{
    Use(&'a SRS<G>),
    Generate
}

impl<'a, G: CommitmentCurve> SRSValue<'a, G> where G::BaseField : PrimeField {
    pub fn generate(size: usize) -> SRS<G> {
        SRS::<G>::create(size)
    }

    pub fn create<'b>(size: usize, spec : SRSSpec<'a, G>) -> SRSValue<'a, G>{
        match spec {
            SRSSpec::Use(x) => SRSValue::Ref(x),
            SRSSpec::Generate => SRSValue::Value(Self::generate(size))
        }
    }
}

pub struct Index<'a, G: CommitmentCurve>
{
    // evaluation domains as multiplicative groups of roots of unity
    pub domains : EvaluationDomains<G::ScalarField>,

    pub gates:  Vec<CircuitGate>,          // circuit gates

    pub sigma:  [Evaluations<Fr<G>>; 3],   // permutation polynomial array
    pub sid:    Evaluations<Fr<G>>,        // SID polynomial

    pub ql:     Evaluations<Fr<G>>,        // left input wire polynomial
    pub qr:     Evaluations<Fr<G>>,        // right input wire polynomial
    pub qo:     Evaluations<Fr<G>>,        // output wire polynomial
    pub qm:     Evaluations<Fr<G>>,        // multiplication polynomial
    pub qc:     Evaluations<Fr<G>>,        // constant wire polynomial

    // polynomial commitment keys
    pub srs: SRSValue<'a, G>,

    // random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<Fr<G>>,
    pub fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
}

pub struct MatrixValues<C: AffineCurve> {
    pub row : PolyComm<C>,
    pub col : PolyComm<C>,
    pub val : PolyComm<C>,
    pub rc : PolyComm<C>,
}

pub struct VerifierIndex<'a, G: CommitmentCurve>
{
    pub h_group: EvaluationDomain<Fr<G>>,

    // polynomial commitment keys
    pub srs: SRSValue<'a, G>,

    // random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<Fr<G>>,
    pub fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
}

impl<'a, G: CommitmentCurve> Index<'a, G> where G::BaseField: PrimeField
{
    pub fn verifier_index(&self) -> Result<VerifierIndex<G>, ProofError> {
        Err(ProofError::ProofCreation)
    }

    // this function compiles the circuit from constraints
    pub fn create
    (
        _max_poly_size: usize,
        _fr_sponge_params: ArithmeticSpongeParams<Fr<G>>,
        _fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
        _srs : SRSSpec<'a, G>
    ) -> Result<Self, ProofError>
    {
        Err(ProofError::ProofCreation)
    }

    // This function verifies the consistency of the wire assignements (witness) against the constraints
    //     witness: wire assignement witness
    //     RETURN: verification status
    pub fn verify
    (
        &self,
        witness: &Witness<Fr<G>>
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
