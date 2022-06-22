use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

use ark_poly::Radix2EvaluationDomain as Domain;
use ark_poly::univariate::DensePolynomial;

use kimchi::circuits::wires::PERMUTS;

use crate::plonk::types::VarPolyComm;
use crate::plonk::SELECTORS;


/// The fixed part of the verifier index
/// (same across all relation circuits)
/// 
/// TODO: We should split the Index/SRS in Kimchi, 
/// so that the constant part can be reused.
pub struct ConstIndex<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    pub domain: Domain<G::ScalarField>,
    pub max_poly_size: usize,
    pub zkpm: DensePolynomial<G::ScalarField>,

    // length of the public input
    pub public_input_size: usize,

    // shifts, defines disjoint cosets of H = <\omega>
    // H_i = shift[i] * H, called k_i in the PlonK paper.
    pub shift: [G::ScalarField; PERMUTS],
}

/// The variable part of the verifier index:
/// (which specifies the relation circuit)
///
/// This enables the circuit to specify the relation.
/// i.e. the same verifier circuits can be used
/// for all production rules of the inductive set.
pub struct VarIndex<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    // commitments to gate selector polynomials
    pub gate_selectors: [VarPolyComm<G, 1>; SELECTORS],
    // commitment to permutation
}

/// An index consists of:
///
/// 1. The variable part which specifies the relation circuit
/// 2. A fixed part which specifies row constraints etc.
pub struct Index<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    pub relation: VarIndex<G>,
    pub constant: ConstIndex<G>,
}
