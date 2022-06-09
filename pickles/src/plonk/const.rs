

enum ConstExprResult<F: FftField + PrimeField> {
    Var(Var<F>),
    Const(F)
}

impl <F: FftField + PrimeField> ConstExprResult<F> {
    fn to_var<C: Cs<F>>(&self, cs: &mut C) -> Var<F> {
        match self {
            ConstExprResult::Var(var) => var,
            ConstExprResult::Const(value) => cs.constant(value)
        }

    }
}

impl <F: FftField + PrimeField> From<Var<F>> for ConstExprResult<F> {
    fn from(var: Var<F>) -> Self {
        ConstExprResult::Var(var)
    }
}

impl <F: FftField + PrimeField> From<F> for ConstExprResult<F> {
    fn from(value: F) -> Self {
        ConstExprResult::Const(value)
    }
}
