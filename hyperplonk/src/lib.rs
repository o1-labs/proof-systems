use ark_ff::Field;
use kimchi::circuits::{
    expr::{ConstantExpr, Expr, ExprInner, Variable},
    gate::CurrOrNext,
};

#[derive(PartialEq)]
enum Column<const N: usize> {
    X(usize),
}

impl<const N: usize> Column<N> {
    pub fn x(i: usize) -> Self {
        assert!(i < N);
        Self::X(i)
    }
}

const MU: usize = 10;
pub type Col = Column<MU>;

pub type E<F, Col> = Expr<ConstantExpr<F>, Col>;

pub fn curr_cell<F: Field>(col: Col) -> E<F, Col> {
    E::Atom(ExprInner::Cell(Variable {
        col,
        row: CurrOrNext::Curr,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;

    #[test]
    fn test() {
        let x_0 = curr_cell::<Fr>(Col::x(3));
        let x_1 = curr_cell::<Fr>(Col::x(1));
        let x_2 = curr_cell::<Fr>(Col::x(2));
        // let p = x_1 + x_2;
        // println!("{:}", p);
        // println!("Degree of p: {:?}", p.degree(1, 0));
    }
}
