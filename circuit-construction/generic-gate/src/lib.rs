use proc_macro::TokenStream;

mod constants;
mod parse;
mod types;

use constants::*;
use parse::{group, seperator};
use types::{Assignment, Coeff, Const, Expr, Operator, Var, Vars, C};

fn mul(l: Option<usize>, r: Option<usize>) -> Option<String> {
    Some(format!("{{ {NAME_E1}.{} * {NAME_E2}.{} }}", l?, r?))
}

fn sub(t1: Option<usize>, t2: Option<usize>) -> Option<String> {
    match (t1, t2) {
        (Some(v1), Some(v2)) => Some(format!("{NAME_E1}.{v1} - {NAME_E2}.{v2}")),
        (Some(v1), None) => Some(format!("{NAME_E1}.{v1}")),
        (None, Some(v2)) => Some(format!("-{NAME_E2}.{v2}")),
        _ => None,
    }
}

fn add(t1: Option<usize>, t2: Option<usize>) -> Option<String> {
    match (t1, t2) {
        (Some(v1), Some(v2)) => Some(format!("{NAME_E1}.{} + {NAME_E2}.{}", v1, v2)),
        (Some(v1), None) => Some(format!("{NAME_E1}.{}", v1)),
        (None, Some(v2)) => Some(format!("{NAME_E2}.{}", v2)),
        _ => None,
    }
}

fn add_seq(t: &[Option<String>]) -> Option<String> {
    let mut terms = t
        .iter()
        .filter(|v| v.is_some())
        .map(|v| v.as_ref().unwrap());

    let mut sum = terms.next()?.clone();

    for ti in terms {
        sum.push_str(" + ");
        sum.push_str(&ti);
    }

    Some(sum)
}

fn to_coeff(terms: Vec<(C, Option<String>)>) -> (Coeff, String) {
    let (coeff, sums): (Vec<C>, Vec<String>) = terms
        .into_iter()
        .filter(|(_, sum)| sum.is_some())
        .map(|(name, sum)| (name, sum.unwrap()))
        .unzip();

    let coeff = Coeff::from(coeff);

    let mut tuple = String::new();

    // compute tuple terms
    tuple.push_str("(");
    for sum in sums.iter() {
        tuple.push_str(&format!("{sum},"));
    }
    tuple.push_str(")");

    (coeff, tuple)
}

impl Expr {
    fn compile(&self, assignment: &Assignment) -> (Coeff, String) {
        match self {
            Expr::Const(con) => match con {
                Const::Literal(literal) => (
                    Coeff::from(vec![C::CST]),
                    format!("({},)", literal.to_string()),
                ),
                Const::Ident(ident) => (
                    Coeff::from(vec![C::CST]),
                    format!("({},)", ident.to_string()),
                ),
            },

            Expr::Var(var) => (
                Coeff::from(vec![assignment.lookup(*var)]),
                format!("({CONST_ONE},)"),
            ),
            Expr::Op(op, expr1, expr2) => {
                let (c1, e1) = expr1.compile(assignment);
                let (c2, e2) = expr2.compile(assignment);

                let terms = match op {
                    Operator::Mul => vec![
                        (
                            C::A,
                            add_seq(&[mul(c1.a(), c2.cst()), mul(c2.a(), c1.cst())]),
                        ),
                        (
                            C::B,
                            add_seq(&[mul(c1.b(), c2.cst()), mul(c2.b(), c1.cst())]),
                        ),
                        (
                            C::C,
                            add_seq(&[mul(c1.c(), c2.cst()), mul(c2.c(), c1.cst())]),
                        ),
                        (
                            C::AB,
                            add_seq(&[
                                mul(c2.cst(), c1.ab()),
                                mul(c2.cst(), c2.ab()),
                                mul(c1.a(), c2.b()),
                                mul(c2.a(), c1.b()),
                            ]),
                        ),
                        (C::CST, mul(c1.cst(), c2.cst())),
                    ],
                    Operator::Add => vec![
                        (C::A, add(c1.a(), c2.a())),
                        (C::B, add(c1.b(), c2.b())),
                        (C::C, add(c1.c(), c2.c())),
                        (C::AB, add(c1.ab(), c2.ab())),
                        (C::CST, add(c1.cst(), c2.cst())),
                    ],
                    Operator::Sub => vec![
                        (C::A, sub(c1.a(), c2.a())),
                        (C::B, sub(c1.b(), c2.b())),
                        (C::C, sub(c1.c(), c2.c())),
                        (C::AB, sub(c1.ab(), c2.ab())),
                        (C::CST, sub(c1.cst(), c2.cst())),
                    ],
                };

                let (coeff, tuple) = to_coeff(terms);

                (
                    coeff,
                    format!(
                        "{{ let {NAME_E1} = {}; let {NAME_E2} = {}; {} }}",
                        e1, e2, tuple
                    ),
                )
            }
        }
    }

    // checks (at compile time) that the expr
    // can be implemnted using a generic gate,
    // i.e. it does not have too high degree.
    //
    // And figures out the assignment of a,b,c.
    fn compute_assigment(&self) -> Assignment {
        fn variables(expr: &Expr) -> Vec<Var> {
            match expr {
                Expr::Var(var) => vec![*var],
                Expr::Op(_, l, r) => {
                    let mut vars = variables(&l);
                    vars.append(&mut variables(&r));
                    vars.sort();
                    vars.dedup();
                    vars
                }
                _ => vec![],
            }
        }

        fn check_muls(expr: &Expr) -> Option<[Var; 2]> {
            match expr {
                Expr::Var(_) => None,
                Expr::Op(op, l, r) => {
                    let vl = variables(l);
                    let vr = variables(r);

                    let ml = check_muls(l);
                    let mr = check_muls(r);

                    match op {
                        Operator::Mul => {
                            match (vl.len(), vr.len(), ml, mr) {
                                // exactly one var on both sides of the mul
                                (1, 1, None, None) => {
                                    let mut m = [vl[0], vr[0]];
                                    m.sort();
                                    Some(m)
                                }
                                // mul by constant
                                (0, _, None, m) => m,
                                (_, 0, m, None) => m,
                                // multiple vars on either side
                                _ => {
                                    panic!("generic gate has too high multiplicative degree")
                                }
                            }
                        }
                        // linear operator: check that we dont
                        // have multiple distinct multiplications
                        _ => {
                            if ml == mr {
                                return ml;
                            }
                            if ml.is_none() {
                                return mr;
                            }
                            if mr.is_none() {
                                return ml;
                            }
                            // both Some and not the same :(
                            panic!("more than 1 distinct multiplication")
                        }
                    }
                }
                _ => None,
            }
        }

        // find the set of variables used (including free term)
        let vars = variables(self);
        assert!(vars.len() <= 3);

        // figure out which variables corresponds to a,b,c resp.
        match check_muls(self) {
            Some(mul) => {
                // find c variable (if used)
                let mut c = None;
                for var in vars.iter() {
                    if !mul.contains(var) {
                        c = Some(*var)
                    }
                }

                // assign a and b
                Assignment {
                    a: Some(mul[0]),
                    b: Some(mul[1]),
                    c,
                }
            }
            None => {
                let mut v = vars.iter().copied();
                Assignment {
                    a: v.next(),
                    b: v.next(),
                    c: v.next(),
                }
            }
        }
    }
}

/// Transforms a generic assert into a generic gate
#[proc_macro]
pub fn generic(input: TokenStream) -> TokenStream {
    //let mut args = vec![];

    let org = input.clone();

    let mut args = input.into_iter();

    let cs = args.next().expect("cs missing");

    seperator(&mut args, ',').expect("missing ',' seperator");

    let vars = Vars::parse(args.next().expect("variable failed to parse"));

    seperator(&mut args, ':').expect("missing ':' seperator");

    let expr = Expr::parse_top(&vars, group(&mut args).expect("missing 'relation' group"))
        .unwrap();

    // check that the constraints can be enforced using a generic gate
    let assignment = expr.compute_assigment();

    // compile expression for computing coefficients
    let (coeff, e) = expr.compile(&assignment);

    // convert to generic gate
    let cs = cs.to_string();

    let mut prog = String::new();
    prog.push_str("{\n");
    prog.push_str(&format!("// expansion of: generic!({})\n", org.to_string()));
    prog.push_str("// imports and constants\n");
    prog.push_str("use ark_ff::{Zero, One};\n");
    prog.push_str(&format!("fn {CONST_ONE}_func<C: Cs<F>, F: FftField + PrimeField>(_cs: &mut C) -> F {{ F::one() }};\n"));
    prog.push_str(&format!("fn {CONST_ZERO}_func<C: Cs<F>, F: FftField + PrimeField>(_cs: &mut C) -> F {{ F::zero() }};\n"));
    prog.push_str(&format!("let {CONST_ONE} = {CONST_ONE}_func({cs});\n"));
    prog.push_str(&format!("let {CONST_ZERO} = {CONST_ZERO}_func({cs});\n"));
    prog.push_str("\n");

    // coefficient vector
    prog.push_str("// evaluate coefficients\n");
    prog.push_str(&format!("let {NAME_E} = {e};\n"));

    // if free variable is present compute the witness
    let solution = match assignment {
        Assignment {
            a: Some(Var::Free),
            b: Some(Var::Free),
            ..
        } => {
            // square relation in ?
            unimplemented!("square relation in free variable not supported")
        }
        Assignment {
            a: Some(Var::Free),
            b,
            c,
        } => {
            let mut num = vec![];
            num.push(
                coeff
                    .index(C::B)
                    .map(|i| format!("{}.val() * {NAME_E}.{i}", vars.name(b.unwrap()))),
            );
            num.push(
                coeff
                    .index(C::C)
                    .map(|i| format!("{}.val() * {NAME_E}.{i}", vars.name(c.unwrap()))),
            );

            let mut denom = vec![];
            denom.push(
                coeff
                    .index(C::AB)
                    .map(|i| format!("{}.val() * {NAME_E}.{i}", vars.name(b.unwrap()))),
            );
            denom.push(coeff.index(C::A).map(|i| format!("{NAME_E}.{i}")));

            Some(format!(
                "({}) / (-({}))",
                add_seq(&num).expect("empty numerator"),
                add_seq(&denom).expect("empty denominator")
            ))
        }
        Assignment {
            a: Some(a),
            b: Some(b),
            c: Some(Var::Free),
        } => {
            assert_ne!(a, Var::Free);
            assert_ne!(b, Var::Free);

            let a = vars.name(a);
            let b = vars.name(b);

            let mut terms = vec![];

            terms.push(
                coeff
                    .index(C::AB)
                    .map(|i| format!("{a}.val() * {b}.val() * {NAME_E}.{i}")),
            );
            terms.push(
                coeff
                    .index(C::A)
                    .map(|i| format!("{a}.val() * {NAME_E}.{i}")),
            );
            terms.push(
                coeff
                    .index(C::B)
                    .map(|i| format!("{b}.val() * {NAME_E}.{i}")),
            );

            let sum = add_seq(&terms).expect("empty numerator");

            // divide sum by -c coefficient
            coeff
                .index(C::C)
                .map(|i| format!("({sum}) / (-{NAME_E}.{i})"))
        }
        _ => None,
    };

    if let Some(solution) = solution.as_ref() {
        prog.push_str("\n// compute witness\n");
        prog.push_str(&format!(
            "let {NAME_FREE_VAR} = {cs}.var(|| {{ {solution} }});\n"
        ));
    }

    let columns = assignment.columns();

    {
        prog.push_str(&format!("let {NAME_WITNESSES} = ("));
        let terms: Vec<String> = (0..3)
            .map(|i| match columns.get(i) {
                Some(var) => format!("{}", vars.name(*var)),
                None => format!("{cs}.var(|| {CONST_ZERO})"),
            })
            .collect();
        prog.push_str(&terms.join(","));
        prog.push_str(");\n");
    }

    prog.push_str("\n// add constraint \n");
    prog.push_str(&format!("{cs}.generic_assert(\n"));
    prog.push_str(&format!("    {NAME_WITNESSES},\n"));
    prog.push_str("    [\n");

    for c in C::COLUMNS.iter().copied() {
        prog.push_str(&match coeff.index(c) {
            Some(i) => format!("        {NAME_E}.{i},\n"),
            None => format!("        {CONST_ZERO},\n"),
        })
    }
    prog.push_str("    ],\n");
    prog.push_str(");");

    // return free variable
    if let Some(_) = solution.as_ref() {
        prog.push_str("\n\n// return the assigment to the free variable\n");
        prog.push_str(&format!("{NAME_FREE_VAR}\n"));
    }
    prog.push_str("}");

    // convert to token stream
    prog.parse().expect("generated program failed to parse")
}
