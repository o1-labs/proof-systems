/*****************************************************************************************************************

This source file implements Plonk Protocol Index primitive.

*****************************************************************************************************************/

use ark_ec::AffineCurve;
use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, Radix2EvaluationDomain as D};
use array_init::array_init;
use commitment_dlog::{
    commitment::{CommitmentCurve, PolyComm},
    srs::SRS,
    CommitmentField,
};
use oracle::poseidon::{ArithmeticSpongeParams, PlonkSpongeConstants15W, SpongeConstants};
use plonk_15_wires_circuits::{
    polynomials::{chacha, lookup},
    gate::{LookupInfo, LookupsUsed},
    expr::{PolishToken, Expr, Column, Linearization},
    gates::poseidon::ROUNDS_PER_ROW,
    nolookup::constraints::{zk_w3, ConstraintSystem},
    wires::*,
};

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

pub enum SRSValue<'a, G: CommitmentCurve> {
    Value(SRS<G>),
    Ref(&'a SRS<G>),
}

impl<'a, G: CommitmentCurve> SRSValue<'a, G> {
    pub fn get_ref(&self) -> &SRS<G> {
        match self {
            SRSValue::Value(x) => &x,
            SRSValue::Ref(x) => x,
        }
    }
}

pub enum SRSSpec<'a, G: CommitmentCurve> {
    Use(&'a SRS<G>),
    Generate(usize),
}

impl<'a, G: CommitmentCurve> SRSValue<'a, G>
where
    G::BaseField: PrimeField,
    G::ScalarField: CommitmentField,
{
    pub fn generate(size: usize) -> SRS<G> {
        SRS::<G>::create(size)
    }

    pub fn create<'b>(spec: SRSSpec<'a, G>) -> SRSValue<'a, G> {
        match spec {
            SRSSpec::Use(x) => SRSValue::Ref(x),
            SRSSpec::Generate(size) => SRSValue::Value(Self::generate(size)),
        }
    }
}

pub struct Index<'a, G: CommitmentCurve>
where
    G::ScalarField: CommitmentField,
{
    /// constraints system polynomials
    pub cs: ConstraintSystem<Fr<G>>,

    pub lookup_used: Option<LookupsUsed>,
    pub linearization: Linearization<Vec<PolishToken<Fr<G>>>>,

    /// polynomial commitment keys
    pub srs: SRSValue<'a, G>,

    /// maximal size of polynomial section
    pub max_poly_size: usize,

    /// maximal size of the quotient polynomial according to the supported constraints
    pub max_quot_size: usize,

    /// random oracle argument parameters
    pub fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
}

// TODO(mimoo): a lot of this stuff is kinda redundant with the Index/ProverIndex. There probably should be a "commonIndex" and then a ProverIndex and VerifierIndex that includes it.
pub struct VerifierIndex<'a, G: CommitmentCurve> {
    /// evaluation domain
    pub domain: D<Fr<G>>,
    /// maximal size of polynomial section
    pub max_poly_size: usize,
    /// maximal size of the quotient polynomial according to the supported constraints
    pub max_quot_size: usize,
    /// polynomial commitment keys
    pub srs: SRSValue<'a, G>,

    // index polynomial commitments
    /// permutation commitment array
    pub sigma_comm: [PolyComm<G>; PERMUTS],
    /// wire commitment array
    pub qw_comm: [PolyComm<G>; GENERICS],
    /// multiplication commitment
    pub qm_comm: PolyComm<G>,
    /// constant wire commitment
    pub qc_comm: PolyComm<G>,

    // poseidon polynomial commitments
    /// round constant polynomial commitment array
    pub rcm_comm: [[PolyComm<G>; PlonkSpongeConstants15W::SPONGE_WIDTH]; ROUNDS_PER_ROW],
    /// poseidon constraint selector polynomial commitment
    pub psm_comm: PolyComm<G>,

    // ECC arithmetic polynomial commitments
    /// EC addition selector polynomial commitment
    pub add_comm: PolyComm<G>,
    /// EC doubling selector polynomial commitment
    pub double_comm: PolyComm<G>,
    /// EC variable base scalar multiplication selector polynomial commitment
    pub mul_comm: PolyComm<G>,
    /// endoscalar multiplication selector polynomial commitment
    pub emul_comm: PolyComm<G>,

    /// Chacha polynomial commitments
    pub chacha_comm: Option<[PolyComm<G>; 4]>,

    /// wire coordinate shifts
    pub shift: [Fr<G>; PERMUTS],
    /// zero-knowledge polynomial
    pub zkpm: DensePolynomial<Fr<G>>,
    // TODO(mimoo): isn't this redundant with domain.d1.group_gen ?
    /// domain offset for zero-knowledge
    pub w: Fr<G>,
    /// endoscalar coefficient
    pub endo: Fr<G>,

    pub lookup_used: Option<LookupsUsed>,
    pub lookup_tables: Vec<Vec<PolyComm<G>>>,
    pub lookup_selectors: Vec<PolyComm<G>>,
    pub linearization: Linearization<Vec<PolishToken<Fr<G>>>>,

    // random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<Fr<G>>,
    pub fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
}

impl<'a, G: CommitmentCurve> Index<'a, G>
where
    G::BaseField: PrimeField,
    G::ScalarField: CommitmentField,
{
    pub fn verifier_index(&self) -> VerifierIndex<G> {
        let srs = match &self.srs {
            SRSValue::Value(s) => SRSValue::Value(s.clone()),
            SRSValue::Ref(x) => SRSValue::Ref(x),
        };

        let domain = self.cs.domain.d1;
        // TODO: Switch to commit_evaluations for all index polys
        VerifierIndex {
            domain,

            sigma_comm: array_init(|i| srs.get_ref().commit_non_hiding(&self.cs.sigmam[i], None)),
            qw_comm: array_init(|i| srs.get_ref().commit_non_hiding(&self.cs.qwm[i], None)),
            qm_comm: srs.get_ref().commit_non_hiding(&self.cs.qmm, None),
            qc_comm: srs.get_ref().commit_non_hiding(&self.cs.qc, None),

            rcm_comm: array_init(|i| {
                array_init(|j| srs.get_ref().commit_non_hiding(&self.cs.rcm[i][j], None))
            }),
            psm_comm: srs.get_ref().commit_non_hiding(&self.cs.psm, None),

            add_comm: srs.get_ref().commit_non_hiding(&self.cs.addm, None),
            double_comm: srs.get_ref().commit_non_hiding(&self.cs.doublem, None),
            mul_comm: srs.get_ref().commit_non_hiding(&self.cs.mulm, None),
            emul_comm: srs.get_ref().commit_non_hiding(&self.cs.emulm, None),

            chacha_comm:
                self.cs.chacha8.as_ref()
                .map(|c| array_init(|i| srs.get_ref().commit_evaluations_non_hiding(domain, &c[i], None))),
            lookup_selectors:
                self.cs.lookup_selectors.iter()
                .map(|e| srs.get_ref().commit_evaluations_non_hiding(domain, e, None))
                .collect(),
            lookup_tables:
                self.cs.lookup_tables8.iter()
                .map(|v| v.iter().map(|e| srs.get_ref().commit_evaluations_non_hiding(domain, e, None)).collect())
                .collect(),

            w: zk_w3(self.cs.domain.d1),
            fr_sponge_params: self.cs.fr_sponge_params.clone(),
            fq_sponge_params: self.fq_sponge_params.clone(),
            endo: self.cs.endo,
            max_poly_size: self.max_poly_size,
            max_quot_size: self.max_quot_size,
            zkpm: self.cs.zkpm.clone(),
            shift: self.cs.shift,
            linearization: self.linearization.clone(),
            lookup_used: self.lookup_used,
            srs,
        }
    }

    // this function compiles the index from constraints
    pub fn create(
        mut cs: ConstraintSystem<Fr<G>>,
        fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
        endo_q: Fr<G>,
        srs: SRSSpec<'a, G>,
    ) -> Self {
        let srs = SRSValue::create(srs);
        let max_poly_size = srs.get_ref().g.len();
        if cs.public > 0 {
            assert!(
                max_poly_size >= cs.domain.d1.size as usize,
                "polynomial segment size has to be not smaller that that of the circuit!"
            );
        }
        cs.endo = endo_q;

        let lookup_info = LookupInfo::<Fr<G>>::create();
        let lookup_used = lookup_info.lookup_used(&cs.gates);

        let linearization = {
            let evaluated_cols = {
                let mut h = std::collections::HashSet::new();
                use Column::*;
                for i in 0..COLUMNS {
                    h.insert(Witness(i));
                }
                for i in 0..(lookup_info.max_per_row + 1) {
                    h.insert(LookupSorted(i));
                }
                h.insert(Z);
                h.insert(LookupAggreg);
                h.insert(LookupTable);
                h
            };
            if lookup_used.is_some() {
                (chacha::constraint(super::range::CHACHA.start)
                    + Expr::combine_constraints(2 + super::range::CHACHA.end,
                        lookup::constraints(
                            &cs.dummy_lookup_values[0], cs.domain.d1)))
                .linearize(evaluated_cols)
                .unwrap()
            } else {
                Linearization {
                    constant_term: 0.into(),
                    index_terms: vec![]
                }
            }
        };

        Index {
            // TODO(mimoo): re-order field like in the type def
            // max_quot_size: PlonkSpongeConstants::SPONGE_BOX * (pcs.cs.domain.d1.size as usize - 1),
            max_quot_size: cs.domain.d8.size as usize - 7,
            fq_sponge_params,
            max_poly_size,
            srs,
            cs,
            lookup_used,
            linearization: linearization.map(|e| e.to_polish())
        }
    }
}
