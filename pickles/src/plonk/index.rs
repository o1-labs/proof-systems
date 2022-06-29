use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

use ark_poly::Radix2EvaluationDomain as Domain;
use ark_poly::univariate::DensePolynomial;

use kimchi::circuits::wires::{COLUMNS, PERMUTS};

use crate::plonk::types::VarPolyComm;
use crate::transcript::{Absorb, Msg, VarSponge};

use circuit_construction::{Constants, Cs};

use kimchi::circuits::expr::{Linearization, PolishToken, ConstantExpr, Expr};

use std::iter;

/// The fixed part of the verifier index
/// (same across all relation circuits)
/// 
/// TODO: We should split the Index/SRS in Kimchi, 
/// so that the constant part can be reused.
pub struct ConstIndex<F: FftField + PrimeField>
{
    pub domain: Domain<F>,
    pub max_poly_size: usize,
    pub zkpm: DensePolynomial<F>,

    // circuit constants
    pub constants: Constants<F>,

    // NOTE: this does not use the RPN framework from Kimchi
    pub linearization: Linearization<Expr<ConstantExpr<F>>>,

    // length of the public input
    pub public_input_size: usize,

    // pub linearization: Linearization<Vec<PolishToken<G::ScalarField>>>,

    // shifts, defines disjoint cosets of H = <\omega>
    // H_i = shift[i] * H, called k_i in the PlonK paper.
    pub shift: [F; PERMUTS],
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
    // index polynomial commitments
    /// permutation commitment array
    pub sigma_comm: [VarPolyComm<G, 1>; PERMUTS],

    /// coefficient commitment array
    pub coefficients_comm: [VarPolyComm<G, 1>; COLUMNS],

    /// coefficient commitment array
    pub generic_comm: VarPolyComm<G, 1>,

    // poseidon polynomial commitments
    /// poseidon constraint selector polynomial commitment
    pub psm_comm: VarPolyComm<G, 1>,

    // ECC arithmetic polynomial commitments
    /// EC addition selector polynomial commitment
    pub complete_add_comm: VarPolyComm<G, 1>,

    /// EC variable base scalar multiplication selector polynomial commitment
    pub mul_comm: VarPolyComm<G, 1>,

    /// endoscalar multiplication selector polynomial commitment
    pub emul_comm: VarPolyComm<G, 1>,

    /// endoscalar multiplication scalar computation selector polynomial commitment
    pub endomul_scalar_comm: VarPolyComm<G, 1>,

    /// Chacha polynomial commitments
    pub chacha_comm: Option<[VarPolyComm<G, 1>; 4]>,

    // Range check gates polynomial commitments
    pub range_check_comm: Vec<VarPolyComm<G, 1>>,
}

impl <G> Absorb<G::BaseField> for VarIndex<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField
{
    fn absorb<C: Cs<G::BaseField>>(&self, cs: &mut C, sponge: &mut VarSponge<G::BaseField>) {
        //
        let comms = iter::empty()
            .chain(&self.sigma_comm)
            .chain(&self.coefficients_comm)
            .chain(iter::once(&self.generic_comm))
            .chain(iter::once(&self.psm_comm))
            .chain(iter::once(&self.complete_add_comm))
            .chain(iter::once(&self.mul_comm))
            .chain(iter::once(&self.emul_comm))
            .chain(iter::once(&self.endomul_scalar_comm))
            .chain(self.chacha_comm.iter().flatten())
            .chain(&self.range_check_comm);

        for p in comms {
            p.absorb(cs, sponge)
        }
    }
}

/// An index consists of:
///
/// 1. The variable part which specifies the relation circuit: 
///    must be absorbed before being touched (for adaptive soundness).
/// 2. A fixed part which specifies row constraints etc.
pub struct Index<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    pub relation: Msg<VarIndex<G>>,
    pub constant: ConstIndex<G::ScalarField>,
}
