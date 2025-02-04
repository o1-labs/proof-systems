use kimchi::circuits::expr::{ConstantExpr, Expr};

pub enum LookupColumns {
    Wires(usize),
    Inverses(usize),
    Acc,
}

pub enum LookupChallengeTerm {
    //The challenge to compute 1/(beta + lookupvalue)
    Beta,
    // The challenge to combine tuple sum beta^i lookupvalue_i
    Gamma,
    // The challenge to combine constraints
    Alpha,
}

pub type ELookup<F> = Expr<ConstantExpr<F, LookupChallengeTerm>, LookupColumns>;
