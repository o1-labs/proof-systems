use crate::{
    columns::ExtendedFoldingColumn,
    decomposable_folding::check_selector,
    expressions::{Degree, FoldingExp, IntegratedFoldingExpr, Sign},
    quadraticization::ExtendedWitnessGenerator,
    EvalLeaf, FoldingConfig, FoldingEnv, RelaxedInstance, RelaxedWitness, ScalarField,
};
use ark_ff::{Field, One};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use kimchi::circuits::expr::Variable;
use poly_commitment::SRS;

/// This type refers to the two instances to be folded
#[derive(Clone, Copy)]
pub enum Side {
    Left = 0,
    Right = 1,
}

impl Side {
    pub fn other(self) -> Self {
        match self {
            Side::Left => Side::Right,
            Side::Right => Side::Left,
        }
    }
}

/// Evaluates the expression in the provided side
pub(crate) fn eval_sided<'a, C: FoldingConfig>(
    exp: &FoldingExp<C>,
    env: &'a ExtendedEnv<C>,
    side: Side,
) -> EvalLeaf<'a, ScalarField<C>> {
    use FoldingExp::*;

    match exp {
        Atom(col) => env.col(col, side),
        Double(e) => {
            let col = eval_sided(e, env, side);
            col.map(Field::double, |f| {
                Field::double_in_place(f);
            })
        }
        Square(e) => {
            let col = eval_sided(e, env, side);
            col.map(Field::square, |f| {
                Field::square_in_place(f);
            })
        }
        Add(e1, e2) => eval_sided(e1, env, side) + eval_sided(e2, env, side),
        Sub(e1, e2) => eval_sided(e1, env, side) - eval_sided(e2, env, side),
        Mul(e1, e2) => {
            //this assumes to some degree that selectors don't multiply each other
            let selector = check_selector(e1)
                .or(check_selector(e2))
                .zip(env.enabled_selector())
                .map(|(s1, s2)| s1 == s2);
            match selector {
                Some(false) => EvalLeaf::Result(env.inner.zero_vec()),
                Some(true) | None => {
                    let d1 = e1.folding_degree();
                    let d2 = e2.folding_degree();
                    let e1 = match d1 {
                        Degree::Two => eval_sided(e1, env, side),
                        _ => eval_exp_error(e1, env, side),
                    };
                    let e2 = match d2 {
                        Degree::Two => eval_sided(e2, env, side),
                        _ => eval_exp_error(e2, env, side),
                    };
                    e1 * e2
                }
            }
        }
        Pow(e, i) => match i {
            0 => EvalLeaf::Const(ScalarField::<C>::one()),
            1 => eval_sided(e, env, side),
            i => {
                let err = eval_sided(e, env, side);
                let mut acc = err.clone();
                for _ in 1..*i {
                    acc = acc * err.clone()
                }
                acc
            }
        },
    }
}

pub(crate) fn eval_exp_error<'a, C: FoldingConfig>(
    exp: &FoldingExp<C>,
    env: &'a ExtendedEnv<C>,
    side: Side,
) -> EvalLeaf<'a, ScalarField<C>> {
    use FoldingExp::*;

    match exp {
        Atom(col) => env.col(col, side),
        Double(e) => {
            let col = eval_exp_error(e, env, side);
            col.map(Field::double, |f| {
                Field::double_in_place(f);
            })
        }
        Square(e) => match exp.folding_degree() {
            Degree::Two => {
                let cross = eval_exp_error(e, env, side) * eval_exp_error(e, env, side.other());
                cross.map(Field::double, |f| {
                    Field::double_in_place(f);
                })
            }
            _ => {
                let e = eval_exp_error(e, env, side);
                e.map(Field::square, |f| {
                    Field::square_in_place(f);
                })
            }
        },
        Add(e1, e2) => eval_exp_error(e1, env, side) + eval_exp_error(e2, env, side),
        Sub(e1, e2) => eval_exp_error(e1, env, side) - eval_exp_error(e2, env, side),
        Mul(e1, e2) => {
            //this assumes to some degree that selectors don't multiply each other
            let selector = check_selector(e1)
                .or(check_selector(e2))
                .zip(env.enabled_selector())
                .map(|(s1, s2)| s1 == s2);
            match selector {
                Some(false) => EvalLeaf::Result(env.inner.zero_vec()),
                Some(true) | None => match (exp.folding_degree(), e1.folding_degree()) {
                    (Degree::Two, Degree::One) => {
                        let first =
                            eval_exp_error(e1, env, side) * eval_exp_error(e2, env, side.other());
                        let second =
                            eval_exp_error(e1, env, side.other()) * eval_exp_error(e2, env, side);
                        first + second
                    }
                    _ => eval_exp_error(e1, env, side) * eval_exp_error(e2, env, side),
                },
            }
        }
        Pow(_, 0) => EvalLeaf::Const(ScalarField::<C>::one()),
        Pow(e, 1) => eval_exp_error(e, env, side),
        Pow(e, 2) => match (exp.folding_degree(), e.folding_degree()) {
            (Degree::Two, Degree::One) => {
                let first = eval_exp_error(e, env, side) * eval_exp_error(e, env, side.other());
                let second = eval_exp_error(e, env, side.other()) * eval_exp_error(e, env, side);
                first + second
            }
            _ => {
                let err = eval_exp_error(e, env, side);
                err.clone() * err
            }
        },
        Pow(e, i) => match exp.folding_degree() {
            Degree::Zero => {
                let e = eval_exp_error(e, env, side);
                // TODO: Implement `pow` here for efficiency
                let mut acc = e.clone();
                for _ in 1..*i {
                    acc = acc * e.clone();
                }
                acc
            }
            _ => panic!("degree over 2"),
        },
    }
}

pub(crate) fn compute_error<C: FoldingConfig>(
    exp: &IntegratedFoldingExpr<C>,
    env: &ExtendedEnv<C>,
    u: (ScalarField<C>, ScalarField<C>),
) -> [Vec<ScalarField<C>>; 2] {
    let (ul, ur) = (u.0, u.1);
    let u_cross = ul * ur;
    let zero = || EvalLeaf::Result(env.inner().zero_vec());

    let t_0 = {
        let t_0 = (zero(), zero());
        let (l, r) = exp.degree_0.iter().fold(t_0, |(l, r), (exp, sign, alpha)| {
            //could be left or right, doesn't matter for constant terms
            let exp = eval_exp_error(exp, env, Side::Left);
            let alpha_l = env.inner().alpha(*alpha, Side::Left);
            let alpha_r = env.inner().alpha(*alpha, Side::Right);
            let left = exp.clone() * alpha_l;
            let right = exp * alpha_r;
            match sign {
                Sign::Pos => (l + left, r + right),
                Sign::Neg => (l - left, r - right),
            }
        });
        let cross2 = u_cross.double();
        let e0 = l.clone() * cross2 + r.clone() * ul.square();
        let e1 = r * cross2 + l * ur.square();
        (e0, e1)
    };

    let t_1 = {
        let t_1 = (zero(), zero(), zero());
        let (l, cross, r) = exp
            .degree_1
            .iter()
            .fold(t_1, |(l, cross, r), (exp, sign, alpha)| {
                let expl = eval_exp_error(exp, env, Side::Left);
                let expr = eval_exp_error(exp, env, Side::Right);
                let alpha_l = env.inner().alpha(*alpha, Side::Left);
                let alpha_r = env.inner().alpha(*alpha, Side::Right);
                let expr_cross = expl.clone() * alpha_r + expr.clone() * alpha_l;
                let left = expl * alpha_l;
                let right = expr * alpha_r;
                match sign {
                    Sign::Pos => (l + left, cross + expr_cross, r + right),
                    Sign::Neg => (l - left, cross - expr_cross, r - right),
                }
            });
        let e0 = cross.clone() * ul + l * ur;
        let e1 = cross.clone() * ur + r * ul;
        (e0, e1)
    };
    let t_2 = (zero(), zero());
    let t_2 = exp.degree_2.iter().fold(t_2, |(l, r), (exp, sign, alpha)| {
        let expl = eval_sided(exp, env, Side::Left);
        let expr = eval_sided(exp, env, Side::Right);
        //left or right matter in some way, but not at the top level call
        let cross = eval_exp_error(exp, env, Side::Left);
        let alpha_l = env.inner().alpha(*alpha, Side::Left);
        let alpha_r = env.inner().alpha(*alpha, Side::Right);
        let left = expl * alpha_r + cross.clone() * alpha_l;
        let right = expr * alpha_l + cross * alpha_r;
        match sign {
            Sign::Pos => (l + left, r + right),
            Sign::Neg => (l - left, r - right),
        }
    });
    let t = [t_1, t_2]
        .into_iter()
        .fold(t_0, |(tl, tr), (txl, txr)| (tl + txl, tr + txr));

    match t {
        (EvalLeaf::Result(l), EvalLeaf::Result(r)) => [l, r],
        _ => unreachable!(),
    }
}

pub(crate) struct ExtendedEnv<CF: FoldingConfig> {
    inner: CF::Env,
    instances: [RelaxedInstance<CF::Curve, CF::Instance>; 2],
    witnesses: [RelaxedWitness<CF::Curve, CF::Witness>; 2],
    domain: Radix2EvaluationDomain<ScalarField<CF>>,
    selector: Option<CF::Selector>,
}

impl<CF: FoldingConfig> ExtendedEnv<CF> {
    pub fn new(
        structure: &CF::Structure,
        //maybe better to have some structure exteded or something like that
        instances: [RelaxedInstance<CF::Curve, CF::Instance>; 2],
        witnesses: [RelaxedWitness<CF::Curve, CF::Witness>; 2],
        domain: Radix2EvaluationDomain<ScalarField<CF>>,
        selector: Option<CF::Selector>,
    ) -> Self {
        let inner_instances = [
            instances[0].inner_instance().inner(),
            instances[1].inner_instance().inner(),
        ];
        let inner_witnesses = [witnesses[0].inner().inner(), witnesses[1].inner().inner()];
        let inner = <CF::Env>::new(structure, inner_instances, inner_witnesses);
        Self {
            inner,
            instances,
            witnesses,
            domain,
            selector,
        }
    }
    pub fn enabled_selector(&self) -> Option<&CF::Selector> {
        self.selector.as_ref()
    }

    pub fn inner(&self) -> &CF::Env {
        &self.inner
    }

    #[allow(clippy::type_complexity)]
    pub fn unwrap(
        self,
    ) -> (
        [RelaxedInstance<CF::Curve, CF::Instance>; 2],
        [RelaxedWitness<CF::Curve, CF::Witness>; 2],
    ) {
        let Self {
            instances,
            witnesses,
            ..
        } = self;
        (instances, witnesses)
    }

    pub fn col(&self, col: &ExtendedFoldingColumn<CF>, side: Side) -> EvalLeaf<ScalarField<CF>> {
        use EvalLeaf::Col;
        use ExtendedFoldingColumn::*;
        let (_instance, witness) = match side {
            Side::Left => (&self.instances[0], &self.witnesses[0]),
            Side::Right => (&self.instances[1], &self.witnesses[1]),
        };
        match col {
            Inner(Variable { col, row }) => Col(self.inner().col(*col, *row, side)),
            WitnessExtended(i) => Col(&witness
                .inner()
                .extended
                .get(i)
                .expect("extended column not present")
                .evals),
            Error => panic!("shouldn't happen"),
            UnnormalizedLagrangeBasis(i) => Col(self.inner().lagrange_basis(*i)),
            Constant(c) => EvalLeaf::Const(*c),
            Challenge(chall) => EvalLeaf::Const(self.inner().challenge(*chall, side)),
            Alpha(i) => EvalLeaf::Const(self.inner().alpha(*i, side)),
            Selector(s) => Col(self.inner().selector(s, side)),
        }
    }

    pub fn col_try(&self, col: &ExtendedFoldingColumn<CF>, side: Side) -> bool {
        use ExtendedFoldingColumn::*;
        let (_instance, witness) = match side {
            Side::Left => (&self.instances[0], &self.witnesses[0]),
            Side::Right => (&self.instances[1], &self.witnesses[1]),
        };
        match col {
            WitnessExtended(i) => witness.inner().extended.get(i).is_some(),
            Error => panic!("shouldn't happen"),
            Inner(_)
            | UnnormalizedLagrangeBasis(_)
            | Constant(_)
            | Challenge(_)
            | Alpha(_)
            | Selector(_) => true,
        }
    }

    pub fn add_witness_evals(&mut self, i: usize, evals: Vec<ScalarField<CF>>, side: Side) {
        let (_instance, witness) = match side {
            Side::Left => (&self.instances[0], &mut self.witnesses[0]),
            Side::Right => (&self.instances[1], &mut self.witnesses[1]),
        };
        let evals = Evaluations::from_vec_and_domain(evals, self.domain);
        witness.inner_mut().add_witness_evals(i, evals);
    }
    pub fn needs_extension(&self, side: Side) -> bool {
        !match side {
            Side::Left => self.witnesses[0].inner().is_extended(),
            Side::Right => self.witnesses[1].inner().is_extended(),
        }
    }

    /// Computes the extended witness column and the corresponding commitments,
    /// updating the innner instance/witness pairs
    pub fn compute_extension(
        self,
        witness_generator: &ExtendedWitnessGenerator<CF>,
        srs: &CF::Srs,
    ) -> Self {
        let env = self;
        let env = witness_generator.compute_extended_witness(env, Side::Left);
        let env = witness_generator.compute_extended_witness(env, Side::Right);
        let env = env.compute_extended_commitments(srs, Side::Left);
        env.compute_extended_commitments(srs, Side::Right)
    }

    fn compute_extended_commitments(mut self, srs: &CF::Srs, side: Side) -> Self {
        let (instance, witness) = match side {
            Side::Left => (&mut self.instances[0], &self.witnesses[0]),
            Side::Right => (&mut self.instances[1], &self.witnesses[1]),
        };

        for (expected_i, (i, wit)) in witness.inner().extended.iter().enumerate() {
            //in case any where to be missing for some reason
            assert_eq!(*i, expected_i);
            let commit = srs.commit_evaluations_non_hiding(self.domain, wit);
            instance.inner_mut().extended.push(commit)
        }
        self
    }
}
