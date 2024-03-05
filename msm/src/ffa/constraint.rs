use ark_ff::Zero;
use ark_poly::Radix2EvaluationDomain;
use num_bigint::BigUint;

use crate::{
    columns::{Column, ColumnIndexer},
    expr::MSMExpr,
    ffa::columns::MSMColumnIndexer,
    lookups::LookupTableIDs,
    proof::ProofInputs,
    witness::Witness,
    {BN254G1Affine, Ff1, Fp, LIMBS_NUM, MSM_FFADD_N_COLUMNS},
};
use kimchi::{
    circuits::{
        expr::{
            Challenges, ColumnEvaluations, ConstantExprInner, Constants, ExprError, ExprInner,
            Operations, Variable,
        },
        gate::CurrOrNext,
    },
    curve::KimchiCurve,
};
use o1_utils::{field_helpers::FieldHelpers, foreign_field::ForeignElement};

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
    pub(crate) d: [T; LIMBS_NUM],
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
    pub fn get_witness(&self) -> ProofInputs<MSM_FFADD_N_COLUMNS, BN254G1Affine, LookupTableIDs> {
        let mut cols: [Vec<Fp>; MSM_FFADD_N_COLUMNS] = std::array::from_fn(|_| vec![]);

        for wc in &self.witness_raw {
            let WitnessColumnsIndexer {
                a: wc_a,
                b: wc_b,
                c: wc_c,
                d: wc_d,
            } = wc;
            for i in 0..LIMBS_NUM {
                cols[i].push(wc_a[i]);
                cols[LIMBS_NUM + i].push(wc_b[i]);
                cols[2 * LIMBS_NUM + i].push(wc_c[i]);
                cols[3 * LIMBS_NUM + i].push(wc_d[i]);
            }
        }

        ProofInputs {
            evaluations: Witness { cols },
            mvlookups: vec![],
        }
    }

    /// Access exprs generated in the environment so far.
    pub fn get_exprs_add(&self) -> Vec<MSMExpr<Fp>> {
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

    // TEST
    pub fn get_exprs_mul(&self) -> Vec<MSMExpr<Fp>> {
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
                let d_i = MSMExpr::Atom(ExprInner::Cell(Variable {
                    col: MSMColumnIndexer::D(i).ix_to_column(),
                    row: CurrOrNext::Curr,
                }));
                a_i * b_i - d_i
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
        self.get_exprs_add()
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
        let d_limbs: [Fp; LIMBS_NUM] = [Zero::zero(); LIMBS_NUM];

        self.witness_raw.push(WitnessColumnsIndexer {
            a: a_limbs,
            b: b_limbs,
            c: c_limbs,
            d: d_limbs,
        });
    }

    pub fn add_test_multiplication(&mut self, a: Ff1, b: Ff1) {
        let a_limbs: [Fp; LIMBS_NUM] = limb_decompose(&a);
        let b_limbs: [Fp; LIMBS_NUM] = limb_decompose(&b);
        let d_limbs_vec: Vec<Fp> = a_limbs
            .iter()
            .zip(b_limbs.iter())
            .map(|(ai, bi)| *ai * *bi)
            .collect();
        let d_limbs: [Fp; LIMBS_NUM] = d_limbs_vec
            .try_into()
            .unwrap_or_else(|_| panic!("Length mismatch"));

        let c_limbs: [Fp; LIMBS_NUM] = [Zero::zero(); LIMBS_NUM];

        self.witness_raw.push(WitnessColumnsIndexer {
            a: a_limbs,
            b: b_limbs,
            c: c_limbs,
            d: d_limbs,
        });
    }
}
