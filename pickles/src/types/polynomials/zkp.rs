use ark_ff::{FftField, PrimeField};

use circuit_construction::{Cs, Var};

use crate::kimchi::index::{ConstIndex, Index};
use crate::util::eval_const_poly;

#[derive(Clone, Debug)]
pub struct ZKPEval<F: FftField + PrimeField> {
    zkp: Var<F>,
}

impl<F: FftField + PrimeField> ZKPEval<F> {
    pub fn new<C: Cs<F>>(cs: &mut C, index: &ConstIndex<F>, zeta: Var<F>) -> Self {
        Self {
            zkp: eval_const_poly(cs, &index.zkpm, zeta),
        }
    }
}

impl<F: FftField + PrimeField> AsRef<Var<F>> for ZKPEval<F> {
    fn as_ref(&self) -> &Var<F> {
        &self.zkp
    }
}
