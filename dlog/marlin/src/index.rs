/*****************************************************************************************************************

This source file implements Marlin Protocol Index primitive.

*****************************************************************************************************************/

use sprs::CsMat;
use commitment_dlog::{srs::SRS, commitment::{CommitmentCurve, PolyComm}};
use algebra::AffineCurve;
use oracle::{rndoracle::ProofError, poseidon::ArithmeticSpongeParams};
use marlin_circuits::{gate::CircuitGate, domains::EvaluationDomains};
pub use super::compiled::Compiled;
use algebra::PrimeField;
use ff_fft::EvaluationDomain;

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
    // constraint system compilation
    pub compiled: [Compiled<G>; 3],

    // evaluation domains as multiplicative groups of roots of unity
    pub domains : EvaluationDomains<G::ScalarField>,

    // number of public inputs
    pub public_inputs: usize,

    // maximal size of polynomial section
    pub max_poly_size: usize,

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
    // constraint system compilation
    pub matrix_commitments: [MatrixValues<G>; 3],

    // evaluation domains as multiplicative groups of roots of unity
    pub domains : EvaluationDomains<Fr<G>>,

    // number of public inputs
    pub public_inputs: usize,

    // maximal size of polynomial section
    pub max_poly_size: usize,

    // polynomial commitment keys
    pub srs: SRSValue<'a, G>,

    // random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<Fr<G>>,
    pub fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
}

impl<'a, G: CommitmentCurve> Index<'a, G> where G::BaseField: PrimeField
{
    fn matrix_values(c : &Compiled<G>) -> MatrixValues<G> {
        MatrixValues {
            row: c.row_comm.clone(),
            col: c.col_comm.clone(),
            val: c.val_comm.clone(),
            rc: c.rc_comm.clone(),
        }
    }

    pub fn verifier_index(&self) -> VerifierIndex<'a, G> {
        let [ a, b, c ] = & self.compiled;

        let srs = match &self.srs {
            SRSValue::Value(s) => SRSValue::Value(s.clone()),
            SRSValue::Ref(x) => SRSValue::Ref(x)
        };

        VerifierIndex {
            matrix_commitments : [ Self::matrix_values(a), Self::matrix_values(b), Self::matrix_values(c) ],
            domains: self.domains,
            public_inputs: self.public_inputs,
            fr_sponge_params: self.fr_sponge_params.clone(),
            fq_sponge_params: self.fq_sponge_params.clone(),
            max_poly_size: self.max_poly_size,
            srs
        }
    }

    // this function compiles the circuit from constraints
    pub fn create
    (
        a: CsMat<Fr<G>>,
        b: CsMat<Fr<G>>,
        c: CsMat<Fr<G>>,
        public_inputs: usize,
        max_poly_size: usize,
        fr_sponge_params: ArithmeticSpongeParams<Fr<G>>,
        fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
        srs : SRSSpec<'a, G>
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

        let srs = SRSValue::create(max_poly_size, srs);

        // compile the constraints
        Ok(Index::<G>
        {
            compiled:
            [
                Compiled::<G>::compile(srs.get_ref(), domains.h, domains.k, domains.b, a)?,
                Compiled::<G>::compile(srs.get_ref(), domains.h, domains.k, domains.b, b)?,
                Compiled::<G>::compile(srs.get_ref(), domains.h, domains.k, domains.b, c)?,
            ],
            fr_sponge_params,
            fq_sponge_params,
            public_inputs,
            max_poly_size, 
            srs,
            domains,
        })
    }

    // This function verifies the consistency of the wire assignements (witness) against the constraints
    //     witness: wire assignement witness
    //     RETURN: verification status
    pub fn verify
    (
        &self,
        witness: &Vec<Fr<G>>
    ) -> bool
    {
        if self.compiled[0].constraints.shape().1 != witness.len() {return false}
        let mut gates = vec![CircuitGate::<Fr<G>>::zero(); self.domains.h.size()];
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
