//! This module implements the prover index as [Prover].

use crate::alphas::Alphas;
use crate::circuits::argument::{Argument, ArgumentType};
use crate::circuits::polynomials::chacha::{ChaCha0, ChaCha1, ChaCha2, ChaChaFinal};
use crate::circuits::polynomials::complete_add::CompleteAdd;
use crate::circuits::polynomials::endomul_scalar::EndomulScalar;
use crate::circuits::polynomials::endosclmul::EndosclMul;
use crate::circuits::polynomials::lookup;
use crate::circuits::polynomials::permutation;
use crate::circuits::polynomials::poseidon::Poseidon;
use crate::circuits::polynomials::varbasemul::VarbaseMul;
use crate::circuits::{
    constraints::{zk_polynomial, zk_w3, ConstraintSystem, LookupConstraintSystem},
    expr::{Column, ConstantExpr, Expr, Linearization, PolishToken},
    gate::{GateType, LookupsUsed},
    wires::*,
};
use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField, SquareRootField};
use ark_poly::{univariate::DensePolynomial, Radix2EvaluationDomain as D};
use array_init::array_init;
use commitment_dlog::{
    commitment::{CommitmentCurve, PolyComm},
    srs::SRS,
};
use oracle::poseidon::ArithmeticSpongeParams;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use std::io::SeekFrom::Start;
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Seek},
    path::Path,
    sync::Arc,
};

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

//~
//~ ### The prover Index
//~

/// The index used by the prover
// TODO: rename as ProverIndex
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct Index<G: CommitmentCurve> {
    /// constraints system polynomials
    #[serde(bound = "ConstraintSystem<Fr<G>>: Serialize + DeserializeOwned")]
    pub cs: ConstraintSystem<Fr<G>>,

    /// The symbolic linearization of our circuit, which can compile to concrete types once certain values are learned in the protocol.
    #[serde(skip)]
    pub linearization: Linearization<Vec<PolishToken<Fr<G>>>>,

    /// The mapping between powers of alpha and constraints
    #[serde(skip)]
    pub powers_of_alpha: Alphas<Fr<G>>,

    /// polynomial commitment keys
    #[serde(skip)]
    pub srs: Arc<SRS<G>>,

    /// maximal size of polynomial section
    pub max_poly_size: usize,

    /// maximal size of the quotient polynomial according to the supported constraints
    pub max_quot_size: usize,

    /// random oracle argument parameters
    #[serde(skip)]
    pub fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
}

//~
//~ #### Linearization
//~

pub fn constraints_expr<F: FftField + SquareRootField>(
    domain: D<F>,
    chacha: bool,
    lookup_constraint_system: &Option<LookupConstraintSystem<F>>,
) -> (Expr<ConstantExpr<F>>, Alphas<F>) {
    // register powers of alpha so that we don't reuse them across mutually inclusive constraints
    let mut powers_of_alpha = Alphas::<F>::default();

    // gates
    let highest_constraints = VarbaseMul::<F>::CONSTRAINTS;
    powers_of_alpha.register(
        ArgumentType::Gate(GateType::VarBaseMul),
        highest_constraints,
    );

    let mut expr = Poseidon::combined_constraints(&powers_of_alpha);
    expr += VarbaseMul::combined_constraints(&powers_of_alpha);
    expr += CompleteAdd::combined_constraints(&powers_of_alpha);
    expr += EndosclMul::combined_constraints(&powers_of_alpha);
    expr += EndomulScalar::combined_constraints(&powers_of_alpha);

    if chacha {
        expr += ChaCha0::combined_constraints(&powers_of_alpha);
        expr += ChaCha1::combined_constraints(&powers_of_alpha);
        expr += ChaCha2::combined_constraints(&powers_of_alpha);
        expr += ChaChaFinal::combined_constraints(&powers_of_alpha);
    }

    // permutation
    powers_of_alpha.register(ArgumentType::Permutation, permutation::CONSTRAINTS);

    // lookup
    if let Some(lcs) = lookup_constraint_system.as_ref() {
        powers_of_alpha.register(ArgumentType::Lookup, lookup::CONSTRAINTS);
        let alphas = powers_of_alpha.get_exponents(ArgumentType::Lookup, lookup::CONSTRAINTS);

        let constraints = lookup::constraints(&lcs.dummy_lookup_values[0], domain);
        let combined = Expr::combine_constraints(alphas, constraints);
        expr += combined;
    }

    // return the expression
    (expr, powers_of_alpha)
}

pub fn linearization_columns<F: FftField + SquareRootField>(
    lookup_constraint_system: &Option<LookupConstraintSystem<F>>,
) -> std::collections::HashSet<Column> {
    let mut h = std::collections::HashSet::new();
    use Column::*;
    for i in 0..COLUMNS {
        h.insert(Witness(i));
    }
    match lookup_constraint_system.as_ref() {
        None => (),
        Some(lcs) => {
            for i in 0..(lcs.max_lookups_per_row + 1) {
                h.insert(LookupSorted(i));
            }
        }
    }
    h.insert(Z);
    h.insert(LookupAggreg);
    h.insert(LookupTable);
    h.insert(Index(GateType::Poseidon));
    h.insert(Index(GateType::Generic));
    h
}

pub fn expr_linearization<F: FftField + SquareRootField>(
    domain: D<F>,
    chacha: bool,
    lookup_constraint_system: &Option<LookupConstraintSystem<F>>,
) -> (Linearization<Vec<PolishToken<F>>>, Alphas<F>) {
    let evaluated_cols = linearization_columns::<F>(lookup_constraint_system);

    let (expr, powers_of_alpha) = constraints_expr(domain, chacha, lookup_constraint_system);

    let linearization = expr
        .linearize(evaluated_cols)
        .unwrap()
        .map(|e| e.to_polish());

    (linearization, powers_of_alpha)
}

//~
//~ #### Prover Index Creation
//~

impl<'a, G: CommitmentCurve> Index<G>
where
    G::BaseField: PrimeField,
{
    /// this function compiles the index from constraints
    pub fn create(
        mut cs: ConstraintSystem<Fr<G>>,
        fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
        endo_q: Fr<G>,
        srs: Arc<SRS<G>>,
    ) -> Self {
        let max_poly_size = srs.g.len();
        if cs.public > 0 {
            assert!(
                max_poly_size >= cs.domain.d1.size as usize,
                "polynomial segment size has to be not smaller that that of the circuit!"
            );
        }
        cs.endo = endo_q;

        //~ 1. compute the linearization
        let (linearization, powers_of_alpha) = expr_linearization(
            cs.domain.d1,
            cs.chacha8.is_some(),
            &cs.lookup_constraint_system,
        );

        //~ 2. set `max_quot_size` to the degree of the quotient polynomial,
        //~    which is obtained by looking at the highest monomial in the sum
        //~     $$\sum_{i=0}^{PERMUTS} (w_i(x) + \beta k_i x + \gamma)$$
        //~    where the $w_i(x)$ are of degree the size of the domain.
        let max_quot_size = PERMUTS * cs.domain.d1.size as usize;

        Index {
            cs,
            linearization,
            powers_of_alpha,
            srs,
            max_poly_size,
            max_quot_size,
            fq_sponge_params,
        }
    }
}

pub mod testing {
    use super::*;
    use crate::circuits::gate::CircuitGate;
    use commitment_dlog::srs::endos;
    use mina_curves::pasta::{pallas::Affine as Other, vesta::Affine, Fp};

    pub fn new_index_for_test(gates: Vec<CircuitGate<Fp>>, public: usize) -> Index<Affine> {
        let fp_sponge_params = oracle::pasta::fp_kimchi::params();
        let cs = ConstraintSystem::<Fp>::create(gates, vec![], fp_sponge_params, public).unwrap();

        let mut srs = SRS::<Affine>::create(cs.domain.d1.size as usize);
        srs.add_lagrange_basis(cs.domain.d1);
        let srs = Arc::new(srs);

        let fq_sponge_params = oracle::pasta::fq_kimchi::params();
        let (endo_q, _endo_r) = endos::<Other>();
        Index::<Affine>::create(cs, fq_sponge_params, endo_q, srs)
    }
}
