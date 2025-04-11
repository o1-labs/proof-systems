//! This module contains the functions used to compute the error terms, as
//! described in the [top-level documentation of the expressions
//! module](crate::expressions).

use crate::{
    columns::ExtendedFoldingColumn,
    decomposable_folding::check_selector,
    eval_leaf::EvalLeaf,
    expressions::{Degree, FoldingExp, IntegratedFoldingExpr, Sign},
    quadraticization::ExtendedWitnessGenerator,
    FoldingConfig, FoldingEnv, Instance, RelaxedInstance, RelaxedWitness, ScalarField,
};
use ark_ff::{Field, One, Zero};
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use kimchi::circuits::expr::Variable;
use poly_commitment::{PolyComm, SRS};

// FIXME: for optimisation, as values are not necessarily Fp elements and are
// relatively small, we could get rid of the scalar field objects, and only use
// bigint where we only apply the modulus when needed.

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
                Some(false) => {
                    let zero_vec = vec![ScalarField::<C>::zero(); env.domain.size as usize];
                    EvalLeaf::Result(zero_vec)
                }
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
                Some(false) => {
                    let zero_vec = vec![ScalarField::<C>::zero(); env.domain.size as usize];
                    EvalLeaf::Result(zero_vec)
                }
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

/// Computes the error terms of a folding/homogeneous expression.
/// The extended environment contains all the evaluations of the columns,
/// including the ones added by the quadraticization process.
/// `u` is the variables used to homogenize the expression.
/// The output is a pair of error terms. To see how it is computed, see the
/// [top-level documentation of the expressions module](crate::expressions).
pub(crate) fn compute_error<C: FoldingConfig>(
    exp: &IntegratedFoldingExpr<C>,
    env: &ExtendedEnv<C>,
    u: (ScalarField<C>, ScalarField<C>),
) -> [Vec<ScalarField<C>>; 2] {
    // FIXME: for speed, use inplace operations, and avoid cloning and
    // allocating a new element.
    // An allocation can cost a third of the time required for an addition and a
    // 9th for a multiplication on the scalar field
    // Indirections are also costly, so we should avoid them as much as
    // possible, and inline code.
    let (ul, ur) = (u.0, u.1);
    let u_cross = ul * ur;
    let zero_vec = vec![ScalarField::<C>::zero(); env.domain.size as usize];
    let zero = || EvalLeaf::Result(zero_vec.clone());

    let alphas_l = env
        .get_relaxed_instance(Side::Left)
        .extended_instance
        .instance
        .get_alphas();
    let alphas_r = env
        .get_relaxed_instance(Side::Right)
        .extended_instance
        .instance
        .get_alphas();

    let t_0 = {
        let t_0 = (zero(), zero());
        let (l, r) = exp.degree_0.iter().fold(t_0, |(l, r), (exp, sign, alpha)| {
            //could be left or right, doesn't matter for constant terms
            let exp = eval_exp_error(exp, env, Side::Left);
            let alpha_l = alphas_l.get(*alpha).expect("alpha not present");
            let alpha_r = alphas_r.get(*alpha).expect("alpha not present");
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
                let alpha_l = alphas_l.get(*alpha).expect("alpha not present");
                let alpha_r = alphas_r.get(*alpha).expect("alpha not present");
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
        let alpha_l = alphas_l.get(*alpha).expect("alpha not present");
        let alpha_r = alphas_r.get(*alpha).expect("alpha not present");
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

/// An extended environment contains the evaluations of all the columns, including
/// the ones added by the quadraticization process. It also contains the
/// the two instances and witnesses that are being folded.
/// The domain is required to define the polynomial size of the evaluations of
/// the error terms.
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
        // maybe better to have some structure extended or something like that
        instances: [RelaxedInstance<CF::Curve, CF::Instance>; 2],
        witnesses: [RelaxedWitness<CF::Curve, CF::Witness>; 2],
        domain: Radix2EvaluationDomain<ScalarField<CF>>,
        selector: Option<CF::Selector>,
    ) -> Self {
        let inner_instances = [
            &instances[0].extended_instance.instance,
            &instances[1].extended_instance.instance,
        ];
        let inner_witnesses = [
            &witnesses[0].extended_witness.witness,
            &witnesses[1].extended_witness.witness,
        ];
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

    pub fn get_relaxed_instance(&self, side: Side) -> &RelaxedInstance<CF::Curve, CF::Instance> {
        &self.instances[side as usize]
    }

    pub fn get_relaxed_witness(&self, side: Side) -> &RelaxedWitness<CF::Curve, CF::Witness> {
        &self.witnesses[side as usize]
    }

    pub fn col(&self, col: &ExtendedFoldingColumn<CF>, side: Side) -> EvalLeaf<ScalarField<CF>> {
        use EvalLeaf::Col;
        use ExtendedFoldingColumn::*;
        let relaxed_instance = self.get_relaxed_instance(side);
        let relaxed_witness = self.get_relaxed_witness(side);
        let alphas = relaxed_instance.extended_instance.instance.get_alphas();
        match col {
            Inner(Variable { col, row }) => Col(self.inner.col(*col, *row, side)),
            WitnessExtended(i) => Col(&relaxed_witness
                .extended_witness
                .extended
                .get(i)
                .expect("extended column not present")
                .evals),
            Error => panic!("shouldn't happen"),
            Constant(c) => EvalLeaf::Const(*c),
            Challenge(chall) => EvalLeaf::Const(self.inner.challenge(*chall, side)),
            Alpha(i) => {
                let alpha = alphas.get(*i).expect("alpha not present");
                EvalLeaf::Const(alpha)
            }
            Selector(s) => Col(self.inner.selector(s, side)),
        }
    }

    pub fn col_try(&self, col: &ExtendedFoldingColumn<CF>, side: Side) -> bool {
        use ExtendedFoldingColumn::*;
        let relaxed_witness = self.get_relaxed_witness(side);
        match col {
            WitnessExtended(i) => relaxed_witness.extended_witness.extended.contains_key(i),
            Error => panic!("shouldn't happen"),
            Inner(_) | Constant(_) | Challenge(_) | Alpha(_) | Selector(_) => true,
        }
    }

    pub fn add_witness_evals(&mut self, i: usize, evals: Vec<ScalarField<CF>>, side: Side) {
        let (_instance, relaxed_witness) = match side {
            Side::Left => (&self.instances[0], &mut self.witnesses[0]),
            Side::Right => (&self.instances[1], &mut self.witnesses[1]),
        };
        let evals = Evaluations::from_vec_and_domain(evals, self.domain);
        relaxed_witness.extended_witness.add_witness_evals(i, evals);
    }

    pub fn needs_extension(&self, side: Side) -> bool {
        !match side {
            Side::Left => self.witnesses[0].extended_witness.is_extended(),
            Side::Right => self.witnesses[1].extended_witness.is_extended(),
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

    // FIXME: use reference to avoid indirect copying/cloning.
    /// Computes the commitments of the columns added by quadriaticization, for
    /// the given side.
    /// The commitments are added to the instance, in the same order for both
    /// side.
    /// Note that this function is only going to be called on the left instance
    /// once. When we fold the second time, the left instance will already be
    /// relaxed and will have the extended columns.
    /// Therefore, the blinder is always the one provided by the user, and it is
    /// saved in the field `blinder` in the case of a relaxed instance that has
    /// been built from a non-relaxed one.
    fn compute_extended_commitments(mut self, srs: &CF::Srs, side: Side) -> Self {
        let (relaxed_instance, relaxed_witness) = match side {
            Side::Left => (&mut self.instances[0], &self.witnesses[0]),
            Side::Right => (&mut self.instances[1], &self.witnesses[1]),
        };

        // FIXME: use parallelisation
        let blinder = PolyComm::new(vec![relaxed_instance.blinder]);
        for (expected_i, (i, with)) in relaxed_witness.extended_witness.extended.iter().enumerate() {
            // in case any where to be missing for some reason
            assert_eq!(*i, expected_i);
            // Blinding the commitments to support the case the witness is zero.
            // The IVC circuit expects to have non-zero commitments.
            let commit = srs
                .commit_evaluations_custom(self.domain, with, &blinder)
                .unwrap()
                .commitment;
            relaxed_instance.extended_instance.extended.push(commit)
        }
        // FIXME: maybe returning a value is not necessary as it does inplace operations.
        // It implies copying on the stack and possibly copy multiple times.
        self
    }

    /// Return the list of scalars and commitments to be absorbed, by
    /// concatenating the ones of the left with the ones of the right instance
    pub(crate) fn to_absorb(
        &self,
        t0: &CF::Curve,
        t1: &CF::Curve,
    ) -> (Vec<ScalarField<CF>>, Vec<CF::Curve>) {
        let mut left = self.instances[0].to_absorb();
        let right = self.instances[1].to_absorb();

        left.0.extend(right.0);
        left.1.extend(right.1);
        left.1.extend([t0, t1]);
        left
    }
}
