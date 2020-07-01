/*****************************************************************************************************************

This source file implements Plonk Protocol Index primitive.

*****************************************************************************************************************/

use commitment_dlog::{srs::SRS, commitment::{CommitmentCurve, PolyComm}};
use ff_fft::{DensePolynomial, Radix2EvaluationDomain as D};
use plonk_circuits::constraints::ConstraintSystem;
use oracle::poseidon::ArithmeticSpongeParams;
use algebra::{AffineCurve, Zero, One};
use array_init::array_init;
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
    pub domain: D<Fr<G>>,          // evaluation domain
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

    // poseidon polynomial commitments
    pub rcm_comm:   [PolyComm<G>; 3],   // round constant polynomia commitment array
    pub fpm_comm:   PolyComm<G>,        // full/partial round indicator polynomial commitment
    pub pfm_comm:   PolyComm<G>,        // partial/full round indicator polynomial commitment
    pub psm_comm:   PolyComm<G>,        // poseidon constraint selector polynomialcommitment

    // EC addition polynomial commitments
    pub add1_comm:  PolyComm<G>,        // full/partial round indicator polynomial commitment

    pub r:          Fr<G>,              // coordinate shift for right wires
    pub o:          Fr<G>,              // coordinate shift for output wires

    // random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<Fr<G>>,
    pub fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
}

impl<'a, G: CommitmentCurve> Index<'a, G> where G::BaseField: PrimeField
{
    pub fn verifier_index(&self) -> VerifierIndex<G> {
        let srs = match &self.srs
        {
            SRSValue::Value(s) => SRSValue::Value(s.clone()),
            SRSValue::Ref(x) => SRSValue::Ref(x)
        };
        
        VerifierIndex
        {
            domain: self.cs.domain.d1,

            sigma_comm: array_init(|i| srs.get_ref().commit(&self.cs.sigmam[i], None)),
            sid_comm: srs.get_ref().commit(&DensePolynomial::from_coefficients_slice(&[Fr::<G>::zero(), Fr::<G>::one()]), None),
            ql_comm: srs.get_ref().commit(&self.cs.qlm, None),
            qr_comm: srs.get_ref().commit(&self.cs.qrm, None),
            qo_comm: srs.get_ref().commit(&self.cs.qom, None),
            qm_comm: srs.get_ref().commit(&self.cs.qmm, None),
            qc_comm: srs.get_ref().commit(&self.cs.qc, None),

            rcm_comm: array_init(|i| srs.get_ref().commit(&self.cs.rcm[i], None)),
            fpm_comm: srs.get_ref().commit(&self.cs.fpm, None),
            pfm_comm: srs.get_ref().commit(&self.cs.pfm, None),
            psm_comm: srs.get_ref().commit(&self.cs.psm, None),

            add1_comm: srs.get_ref().commit(&self.cs.add1m, None),

            fr_sponge_params: self.fr_sponge_params.clone(),
            fq_sponge_params: self.fq_sponge_params.clone(),
            max_poly_size: self.max_poly_size,
            srs,
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
    ) -> Self
    {
        let srs = SRSValue::create(max_poly_size, srs);
        Index
        {
            fr_sponge_params,
            fq_sponge_params,
            max_poly_size,
            srs,
            cs,
        }
    }
}
