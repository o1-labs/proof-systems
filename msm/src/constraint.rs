use ark_poly::Radix2EvaluationDomain;
use num_bigint::BigUint;

use kimchi::circuits::expr::{
    Challenges, ColumnEvaluations, ConstantExpr, ConstantExprInner, Constants, Expr, ExprError,
    ExprInner, Operations, Variable,
};
use kimchi::circuits::gate::CurrOrNext;
use kimchi::curve::KimchiCurve;
use o1_utils::field_helpers::FieldHelpers;
use o1_utils::foreign_field::ForeignElement;

use crate::columns::{Column, ColumnIndexer, MSMColumnIndexer};
use crate::proof::{Witness, WitnessColumns};
use crate::{BN254G1Affine, Ff1, Fp, LIMBS_NUM};

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
fn limb_decompose(input: &Ff1) -> [Fp; LIMBS_NUM] {
    let input_bi: BigUint = FieldHelpers::to_biguint(input);
    let ff_el: ForeignElement<Fp, LIMBS_NUM> = ForeignElement::from_biguint(input_bi);
    ff_el.limbs
}

pub struct WitnessColumnsIndexer<T> {
    pub(crate) a: [T; LIMBS_NUM],
    pub(crate) b: [T; LIMBS_NUM],
    pub(crate) c: [T; LIMBS_NUM],
}

#[allow(dead_code)]
/// Builder environment for a native group `G`.
pub struct MSMCircuitEnv<G: KimchiCurve> {
    /// Aggregated witness, in raw form. For accessing [`Witness`], see the
    /// `get_witness` method.
    witness_raw: Vec<WitnessColumnsIndexer<G::ScalarField>>,
}

impl MSMCircuitEnv<BN254G1Affine> {
    pub fn empty() -> Self {
        MSMCircuitEnv {
            witness_raw: vec![],
        }
    }

    /// Each WitnessColumn stands for both one row and multirow. This
    /// function converts from a vector of one-row instantiation to a
    /// single multi-row form (which is a `Witness`).
    pub fn get_witness(&self) -> Witness<BN254G1Affine> {
        let mut x: Vec<Vec<Fp>> = vec![vec![]; 3 * LIMBS_NUM];

        for wc in &self.witness_raw {
            let WitnessColumnsIndexer {
                a: wc_a,
                b: wc_b,
                c: wc_c,
            } = wc;
            for i in 0..LIMBS_NUM {
                x[i].push(wc_a[i]);
                x[LIMBS_NUM + i].push(wc_b[i]);
                x[2 * LIMBS_NUM + i].push(wc_c[i]);
            }
        }

        Witness {
            evaluations: WitnessColumns { x },
            mvlookups: vec![],
        }
    }

    /// Access exprs generated in the environment so far.
    pub fn get_exprs(&self) -> Vec<MSMExpr<Fp>> {
        let mut limb_exprs: Vec<_> = vec![];
        for i in 0..LIMBS_NUM {
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
            limb_exprs.push(limb_constraint);
        }
        limb_exprs
    }

    pub fn eval_expressions<Evaluations: ColumnEvaluations<Fp, Column = crate::columns::Column>>(
        &self,
        d: Radix2EvaluationDomain<Fp>,
        pt: Fp,
        evals: &Evaluations,
        c: &Constants<Fp>,
        chals: &Challenges<Fp>,
    ) -> Result<Vec<Fp>, ExprError<Column>> {
        self.get_exprs()
            .iter()
            .map(|expr| expr.evaluate_(d, pt, evals, c, chals))
            .collect()
    }

    pub fn add_test_addition(&mut self, a: Ff1, b: Ff1) {
        let a_limbs: [Fp; LIMBS_NUM] = limb_decompose(&a);
        let b_limbs: [Fp; LIMBS_NUM] = limb_decompose(&b);
        let c_limbs_vec: Vec<Fp> = a_limbs
            .iter()
            .zip(b_limbs.iter())
            .map(|(ai, bi)| *ai + *bi)
            .collect();
        let c_limbs: [Fp; LIMBS_NUM] = c_limbs_vec
            .try_into()
            .unwrap_or_else(|_| panic!("Length mismatch"));

        self.witness_raw.push(WitnessColumnsIndexer {
            a: a_limbs,
            b: b_limbs,
            c: c_limbs,
        });
    }
}
