/*****************************************************************************************************************

This source file implements Plonk Protocol Index primitive.

*****************************************************************************************************************/

use commitment_dlog::{srs::SRS, commitment::{CommitmentCurve, PolyComm}};
use ff_fft::{DensePolynomial, Radix2EvaluationDomain as Domain};
use algebra::{AffineCurve, Zero, One};
use oracle::rndoracle::ProofError;
use oracle::poseidon::ArithmeticSpongeParams;
use plonk_circuits::constraints::ConstraintSystem;
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
    // constraints as Lagrange-based polynoms
    pub cs: ConstraintSystem<Fr<G>>,

    // polynomial commitment keys
    pub srs: SRSValue<'a, G>,
    
    // maximal size of polynomial section
    pub max_poly_size: usize,

    // index polynomial commitments
    pub sigma_comm:  [PolyComm<G>; 3],   // permutation commitment array
    pub sid_comm:    PolyComm<G>,        // SID commitment
    pub ql_comm:     PolyComm<G>,        // left input wire commitment
    pub qr_comm:     PolyComm<G>,        // right input wire commitment
    pub qo_comm:     PolyComm<G>,        // output wire commitment
    pub qm_comm:     PolyComm<G>,        // multiplication commitment
    pub qc_comm:     PolyComm<G>,        // constant wire commitment

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
    pub domain: Domain<Fr<G>>,          // evaluation domain
    pub max_poly_size: usize,           // maximal size of polynomial section
    pub srs: SRSValue<'a, G>,           // polynomial commitment keys

    // index polynomial commitments
    pub sigma_comm: [PolyComm<G>; 3],   // permutation commitment array
    pub sid_comm:   PolyComm<G>,        // SID commitment
    pub ql_comm:    PolyComm<G>,        // left input wire commitment
    pub qr_comm:    PolyComm<G>,        // right input wire commitment
    pub qo_comm:    PolyComm<G>,        // output wire commitment
    pub qm_comm:    PolyComm<G>,        // multiplication commitment
    pub qc_comm:    PolyComm<G>,        // constant wire commitment

    pub r:          Fr<G>,              // coordinate shift for right wires
    pub o:          Fr<G>,              // coordinate shift for output wires

    // random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<Fr<G>>,
    pub fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
}

impl<'a, G: CommitmentCurve> Index<'a, G> where G::BaseField: PrimeField
{
    pub fn verifier_index(&self) -> VerifierIndex<G> {
        VerifierIndex
        {
            domain: self.cs.domain.d1,
            sigma_comm: self.sigma_comm.clone(),
            sid_comm: self.sid_comm.clone(),
            ql_comm: self.ql_comm.clone(),
            qr_comm: self.qr_comm.clone(),
            qo_comm: self.qo_comm.clone(),
            qm_comm: self.qm_comm.clone(),
            qc_comm: self.qc_comm.clone(),
            fr_sponge_params: self.fr_sponge_params.clone(),
            fq_sponge_params: self.fq_sponge_params.clone(),
            max_poly_size: self.max_poly_size,
            srs: match &self.srs
            {
                SRSValue::Value(s) => SRSValue::Value(s.clone()),
                SRSValue::Ref(x) => SRSValue::Ref(x)
            },
            r: self.cs.r,
            o: self.cs.o,
        }
    }

    // this function compiles the index from constraints
    pub fn create
    (
        cs: ConstraintSystem<Fr<G>>,
        max_poly_size: usize,
        fr_sponge_params: ArithmeticSpongeParams<Fr<G>>,
        fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
        srs : SRSSpec<'a, G>
    ) -> Result<Self, ProofError>
    {
        let srs = SRSValue::create(max_poly_size, srs);
        Ok(Index
            {
                sigma_comm:
                [
                    srs.get_ref().commit(&cs.sigmam[0], None),
                    srs.get_ref().commit(&cs.sigmam[1], None), 
                    srs.get_ref().commit(&cs.sigmam[2], None)
                ],
                sid_comm: srs.get_ref().commit(&DensePolynomial::from_coefficients_slice(&[Fr::<G>::zero(), Fr::<G>::one()]), None),
                ql_comm: srs.get_ref().commit(&cs.ql, None),
                qr_comm: srs.get_ref().commit(&cs.qr, None),
                qo_comm: srs.get_ref().commit(&cs.qo, None),
                qm_comm: srs.get_ref().commit(&cs.qm, None),
                qc_comm: srs.get_ref().commit(&cs.qc, None),
                fr_sponge_params,
                fq_sponge_params,
                max_poly_size,
                srs,
                cs,
            })
        }
}
