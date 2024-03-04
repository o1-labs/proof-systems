use kimchi::circuits::expr::{ConstantExpr, Expr};
use kimchi::circuits::expr::{ConstantExprInner, Operations};
use kimchi::circuits::expr::{ExprInner, Variable};
use kimchi::circuits::gate::CurrOrNext;
use kimchi::curve::KimchiCurve;
use num_bigint::BigUint;

use o1_utils::field_helpers::FieldHelpers;
use o1_utils::foreign_field::ForeignElement;

use crate::columns::{Column, ColumnIndexer, MSMColumnIndexer};
use crate::proof::ProofInputs;
use crate::witness::Witness;
use crate::{BN254G1Affine, Ff1, Fp, MSM_FFADD_N_COLUMNS, N_LIMBS};

/// Used to represent constraints as multi variate polynomials. The variables
/// are over the columns.
/// For instance, if there are 3 columns X1, X2, X3, then to constraint X3 to be
/// equals to sum of the X1 and X2 on a row, we would use the multivariate
/// polynomial `X3 - X1 - X2 = 0`.
/// Using the expression framework, this constraint would be
/// ```
/// use kimchi::circuits::expr::{ConstantExprInner, ExprInner, Operations, Variable};
/// use kimchi::circuits::gate::CurrOrNext;
/// use kimchi_msm::columns::Column;
/// use kimchi_msm::constraint::MSMExpr;
/// pub type Fp = ark_bn254::Fr;
/// let x1 = MSMExpr::<Fp>::Atom(
///     ExprInner::<Operations<ConstantExprInner<Fp>>, Column>::Cell(Variable {
///         col: Column::X(1),
///         row: CurrOrNext::Curr,
///     }),
/// );
/// let x2 = MSMExpr::<Fp>::Atom(
///     ExprInner::<Operations<ConstantExprInner<Fp>>, Column>::Cell(Variable {
///         col: Column::X(1),
///         row: CurrOrNext::Curr,
///     }),
/// );
/// let x3 = MSMExpr::<Fp>::Atom(
///     ExprInner::<Operations<ConstantExprInner<Fp>>, Column>::Cell(Variable {
///         col: Column::X(1),
///         row: CurrOrNext::Curr,
///     }),
/// );
/// let constraint = x3 - x1 - x2;
/// ```
/// A list of such constraints is used to represent the entire circuit and will
/// be used to build the quotient polynomial.
pub type MSMExpr<F> = Expr<ConstantExpr<F>, Column>;

// TODO use more foreign_field.rs with from/to bigint conversion
fn limb_decompose(input: &Ff1) -> [Fp; N_LIMBS] {
    let input_bi: BigUint = FieldHelpers::to_biguint(input);
    let ff_el: ForeignElement<Fp, N_LIMBS> = ForeignElement::from_biguint(input_bi);
    ff_el.limbs
}

pub struct WitnessColumnsIndexer<T> {
    pub(crate) a: [T; N_LIMBS],
    pub(crate) b: [T; N_LIMBS],
    pub(crate) c: [T; N_LIMBS],
}

#[allow(dead_code)]
/// Builder environment for a native group `G`.
pub struct BuilderEnv<G: KimchiCurve> {
    // TODO something like a running list of constraints
    /// Aggregated constraints.
    pub(crate) constraints: Vec<MSMExpr<G::ScalarField>>,
    /// Aggregated witness, in raw form. For accessing [`Witness`], see the
    /// `get_witness` method.
    pub(crate) witness_raw: Vec<WitnessColumnsIndexer<G::ScalarField>>,
}

impl BuilderEnv<BN254G1Affine> {
    pub fn empty() -> Self {
        BuilderEnv {
            constraints: vec![],
            witness_raw: vec![],
        }
    }

    /// Each WitnessColumn stands for both one row and multirow. This
    /// function converts from a vector of one-row instantiation to a
    /// single multi-row form (which is a `Witness`).
    pub fn get_witness(&self) -> ProofInputs<MSM_FFADD_N_COLUMNS, BN254G1Affine> {
        let mut cols: [Vec<Fp>; MSM_FFADD_N_COLUMNS] = std::array::from_fn(|_| vec![]);

        for wc in &self.witness_raw {
            let WitnessColumnsIndexer {
                a: wc_a,
                b: wc_b,
                c: wc_c,
            } = wc;
            for i in 0..N_LIMBS {
                cols[i].push(wc_a[i]);
                cols[N_LIMBS + i].push(wc_b[i]);
                cols[2 * N_LIMBS + i].push(wc_c[i]);
            }
        }

        ProofInputs {
            evaluations: Witness { cols },
            mvlookups: vec![],
        }
    }

    pub fn add_test_addition(&mut self, a: Ff1, b: Ff1) {
        let mut limb_constraints: Vec<_> = vec![];
        for i in 0..N_LIMBS {
            let limb_constraint = {
                let a_i = MSMExpr::Atom(
                    ExprInner::<Operations<ConstantExprInner<Fp>>, Column>::Cell(Variable {
                        col: MSMColumnIndexer::A(i).ix_to_column(),
                        row: CurrOrNext::Curr,
                    }),
                );
                let b_i = MSMExpr::Atom(ExprInner::Cell(Variable {
                    col: MSMColumnIndexer::B(i).ix_to_column(),
                    row: CurrOrNext::Curr,
                }));
                let c_i = MSMExpr::Atom(ExprInner::Cell(Variable {
                    col: MSMColumnIndexer::C(i).ix_to_column(),
                    row: CurrOrNext::Curr,
                }));
                a_i + b_i - c_i
            };
            limb_constraints.push(limb_constraint);
        }
        let combined_constraint =
            Expr::combine_constraints(0..(limb_constraints.len() as u32), limb_constraints);
        self.constraints.push(combined_constraint);

        let a_limbs: [Fp; N_LIMBS] = limb_decompose(&a);
        let b_limbs: [Fp; N_LIMBS] = limb_decompose(&b);
        let c_limbs_vec: Vec<Fp> = a_limbs
            .iter()
            .zip(b_limbs.iter())
            .map(|(ai, bi)| *ai + *bi)
            .collect();
        let c_limbs: [Fp; N_LIMBS] = c_limbs_vec
            .try_into()
            .unwrap_or_else(|_| panic!("Length mismatch"));

        self.witness_raw.push(WitnessColumnsIndexer {
            a: a_limbs,
            b: b_limbs,
            c: c_limbs,
        });
    }
}
