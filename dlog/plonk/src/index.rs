/*****************************************************************************************************************

This source file implements Plonk Protocol Index primitive.

*****************************************************************************************************************/

use ff_fft::Radix2EvaluationDomain as D;
use commitment_dlog::{srs::SRS, CommitmentField, commitment::{CommitmentCurve, PolyComm}};
use plonk_circuits::constraints::ConstraintSystem;
use oracle::poseidon::ArithmeticSpongeParams;
use array_init::array_init;
use algebra::AffineCurve;
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
    Generate(usize)
}

impl<'a, G: CommitmentCurve> SRSValue<'a, G> where G::BaseField : PrimeField, G::ScalarField : CommitmentField {
    pub fn generate(size: usize) -> SRS<G> {
        SRS::<G>::create(size)
    }

    pub fn create<'b>(spec : SRSSpec<'a, G>) -> SRSValue<'a, G>{
        match spec {
            SRSSpec::Use(x) => SRSValue::Ref(x),
            SRSSpec::Generate(size) => SRSValue::Value(Self::generate(size))
        }
    }
}

pub struct Index<'a, G: CommitmentCurve> where G::ScalarField : CommitmentField
{
    // constraints system polynoms
    pub cs: ConstraintSystem<Fr<G>>,

    // polynomial commitment keys
    pub srs: SRSValue<'a, G>,

    // maximal size of polynomial section
    pub max_poly_size: usize,

    // maximal size of the quotient polynomial according to the supported constraints
    pub max_quot_size: usize,

    // random oracle argument parameters
    pub fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
}

pub struct VerifierIndex<'a, G: CommitmentCurve>
{
    pub domain: D<Fr<G>>,               // evaluation domain
    pub max_poly_size: usize,           // maximal size of polynomial section
    pub max_quot_size: usize,           // maximal size of the quotient polynomial according to the supported constraints
    pub srs: SRSValue<'a, G>,           // polynomial commitment keys

    // index polynomial commitments
    pub sigma_comm: [PolyComm<G>; 3],   // permutation commitment array
    pub ql_comm:    PolyComm<G>,        // left input wire commitment
    pub qr_comm:    PolyComm<G>,        // right input wire commitment
    pub qo_comm:    PolyComm<G>,        // output wire commitment
    pub qm_comm:    PolyComm<G>,        // multiplication commitment
    pub qc_comm:    PolyComm<G>,        // constant wire commitment

    // poseidon polynomial commitments
    pub rcm_comm:   [PolyComm<G>; 3],   // round constant polynomial commitment array
    pub psm_comm:   PolyComm<G>,        // poseidon constraint selector polynomial commitment

    // ECC arithmetic polynomial commitments
    pub add_comm:   PolyComm<G>,        // EC addition selector polynomial commitment
    pub mul1_comm:  PolyComm<G>,        // EC variable base scalar multiplication selector polynomial commitment
    pub mul2_comm:  PolyComm<G>,        // EC variable base scalar multiplication selector polynomial commitment
    pub emul1_comm: PolyComm<G>,        // endoscalar multiplication selector polynomial commitment
    pub emul2_comm: PolyComm<G>,        // endoscalar multiplication selector polynomial commitment
    pub emul3_comm: PolyComm<G>,        // endoscalar multiplication selector polynomial commitment

    pub r:          Fr<G>,              // coordinate shift for right wires
    pub o:          Fr<G>,              // coordinate shift for output wires

    // random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<Fr<G>>,
    pub fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
}

impl<'a, G: CommitmentCurve> Index<'a, G> where G::BaseField: PrimeField, G::ScalarField : CommitmentField
{
    pub fn verifier_index(&self) -> VerifierIndex<G> {
        let srs = match &self.srs
        {
            SRSValue::Value(s) => SRSValue::Value(s.clone()),
            SRSValue::Ref(x) => SRSValue::Ref(x)
        };

        println!("verifier_index");
        println!("cs.qlm {}", self.cs.qlm.coeffs.len());
        println!("cs.qrm {}", self.cs.qrm.coeffs.len());
        println!("cs.qom {}", self.cs.qom.coeffs.len());
        println!("cs.qmm {}", self.cs.qmm.coeffs.len());
        println!("cs.qc {}", self.cs.qc.coeffs.len());

        println!("cs.sigmam[0] {}", self.cs.sigmam[0].coeffs.len());
        println!("cs.sigmam[1] {}", self.cs.sigmam[1].coeffs.len());
        println!("cs.sigmam[2] {}", self.cs.sigmam[2].coeffs.len());

        println!("cs.rcm[0] {}", self.cs.rcm[0].coeffs.len());
        println!("cs.rcm[1] {}", self.cs.rcm[1].coeffs.len());
        println!("cs.rcm[2] {}", self.cs.rcm[2].coeffs.len());

        println!("cs.psm {}", self.cs.psm.coeffs.len());
        println!("cs.addm {}", self.cs.addm.coeffs.len());
        println!("cs.mul1m {}", self.cs.mul1m.coeffs.len());
        println!("cs.mul2m {}", self.cs.mul2m.coeffs.len());

        println!("cs.emul1m {}", self.cs.emul1m.coeffs.len());
        println!("cs.emul2m {}", self.cs.emul2m.coeffs.len());
        println!("cs.emul3m {}", self.cs.emul3m.coeffs.len());

        VerifierIndex
        {
            domain: self.cs.domain.d1,

            sigma_comm: array_init(|i| srs.get_ref().commit(&self.cs.sigmam[i], None)),
            ql_comm: srs.get_ref().commit(&self.cs.qlm, None),
            qr_comm: srs.get_ref().commit(&self.cs.qrm, None),
            qo_comm: srs.get_ref().commit(&self.cs.qom, None),
            qm_comm: srs.get_ref().commit(&self.cs.qmm, None),
            qc_comm: srs.get_ref().commit(&self.cs.qc, None),

            rcm_comm: array_init(|i| srs.get_ref().commit(&self.cs.rcm[i], None)),
            psm_comm: srs.get_ref().commit(&self.cs.psm, None),

            add_comm: srs.get_ref().commit(&self.cs.addm, None),
            mul1_comm: srs.get_ref().commit(&self.cs.mul1m, None),
            mul2_comm: srs.get_ref().commit(&self.cs.mul2m, None),
            emul1_comm: srs.get_ref().commit(&self.cs.emul1m, None),
            emul2_comm: srs.get_ref().commit(&self.cs.emul2m, None),
            emul3_comm: srs.get_ref().commit(&self.cs.emul3m, None),

            fr_sponge_params: self.cs.fr_sponge_params.clone(),
            fq_sponge_params: self.fq_sponge_params.clone(),
            max_poly_size: self.max_poly_size,
            max_quot_size: self.max_quot_size,
            srs,
            r: self.cs.r,
            o: self.cs.o,
        }
    }

    // this function compiles the index from constraints
    pub fn create
    (
        mut cs: ConstraintSystem<Fr<G>>,
        fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
        srs : SRSSpec<'a, G>
    ) -> Self
    {
        let srs = SRSValue::create(srs);
        let max_poly_size = srs.get_ref().g.len();
        if cs.public > 0
        {
            assert!(max_poly_size >= cs.domain.d1.size as usize, "polynomial segment size has to be not smaller that that of the circuit!");
        }
        cs.endo = srs.get_ref().endo_r;
        Index
        {
            max_quot_size: 5 * (cs.domain.d1.size as usize + 2) - 5,
            fq_sponge_params,
            max_poly_size,
            srs,
            cs,
        }
    }
}
