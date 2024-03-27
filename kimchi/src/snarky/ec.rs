//! Functions associated to the EC addition and scaling.

use super::{
    constraint_system::{EcAddCompleteInput, ScaleRound},
    snarky_type::SnarkyType,
};
use crate::{
    snarky::{
        constraint_system::KimchiConstraint,
        prelude::{FieldVar, RunState},
        runner::Constraint,
    },
    SnarkyResult,
};
use ark_ec::{short_weierstrass_jacobian::GroupAffine, SWModelParameters};
use ark_ff::{BigInteger, PrimeField};
use std::{borrow::Cow, marker::PhantomData};

pub fn ec_add<F: PrimeField, C: SWModelParameters<BaseField = F>>(
    runner: &mut RunState<F>,
    loc: Cow<'static, str>,
    a: [FieldVar<F>; 2],
    b: [FieldVar<F>; 2],
) -> SnarkyResult<[FieldVar<F>; 2]> {
    let [a0, a1] = a;
    let [b0, b1] = b;
    let [p3x, p3y, inf, same_x, slope, inf_z, x21_inv]: [FieldVar<F>; 7] =
        runner.compute(loc.clone(), |w| {
            let to_bool = |x| {
                if x {
                    F::from(1_u8)
                } else {
                    F::zero()
                }
            };
            let x1 = w.read_var(&a0);
            let x2 = w.read_var(&a1);
            let y1 = w.read_var(&b0);
            let y2 = w.read_var(&b1);

            let same_x = to_bool(x1 == x2);

            let x_diff = x2 - x1;
            let x21_inv = x_diff.inverse().unwrap();
            let y_diff = y2 - y1;
            let slope = y_diff * x21_inv;

            let a = GroupAffine::<C>::new(x1, y1, false);
            let b = GroupAffine::<C>::new(x2, y2, false);
            assert!(!a.infinity, "can not be infinity");
            assert!(!b.infinity, "can not be infinity");

            let c = a + b;
            let inf = to_bool(c.infinity);

            let inf_z = if y1 == y2 {
                F::zero()
            } else if x1 == x2 {
                y_diff.inverse().unwrap()
            } else {
                F::zero()
            };
            [c.x, c.y, inf, same_x, slope, inf_z, x21_inv]
        })?;
    let p1 = (a0, a1);
    let p2 = (b0, b1);
    let p3 = (p3x.clone(), p3y.clone());
    let c = [p3x, p3y];
    inf.assert_equals(runner, loc.clone(), &FieldVar::zero())?;

    let constraint =
        Constraint::KimchiConstraint(KimchiConstraint::EcAddComplete(EcAddCompleteInput {
            p1,
            p2,
            p3,
            inf,
            same_x,
            slope,
            inf_z,
            x21_inv,
        }));
    runner.add_constraint(constraint, None, loc)?;
    Ok(c)
}

pub fn ec_scale<F: PrimeField, C: SWModelParameters<BaseField = F>>(
    runner: &mut RunState<F>,
    loc: Cow<'static, str>,
    base: [FieldVar<F>; 2],
    scalar: &FieldVar<F>,
) -> SnarkyResult<[FieldVar<F>; 2]> {
    let limbs = split_in_limbs(runner, loc.clone(), scalar)?;
    let limbs: [Limb<F>; 51] = limbs.into();
    let n_prev = FieldVar::zero();
    let state: Option<([FieldVar<F>; 2], FieldVar<F>)> = None;
    let rounds = limbs.into_iter().scan(state, |state, scalar| {
        let round = match state {
            Some((input, n_prev)) => limb_scale::<F, C>(
                runner,
                loc.clone(),
                base.clone(),
                input.clone(),
                scalar,
                n_prev.clone(),
            ),
            None => limb_scale::<F, C>(
                runner,
                loc.clone(),
                base.clone(),
                base.clone(),
                scalar,
                n_prev.clone(),
            ),
        };
        let out = round.as_ref().unwrap().0.clone();
        let n_next = round.as_ref().unwrap().1.n_next.clone();
        *state = Some((out, n_next));
        let round = round.map(|r| r.1);
        Some(round)
    });
    let rounds: SnarkyResult<Vec<ScaleRound<FieldVar<F>>>> = rounds.collect();
    let rounds = rounds?;
    let last = &rounds.last().unwrap();
    last.n_next.equal(runner, loc.clone(), scalar)?;
    let out = last.accs[5].clone();
    runner.add_constraint(
        Constraint::KimchiConstraint(KimchiConstraint::EcScale(rounds)),
        None,
        loc,
    )?;
    Ok(out.into())
}
#[allow(clippy::type_complexity)]
pub fn limb_scale<F: PrimeField, C: SWModelParameters<BaseField = F>>(
    runner: &mut RunState<F>,
    loc: Cow<'static, str>,
    base: [FieldVar<F>; 2],
    input: [FieldVar<F>; 2],
    scalar: Limb<F>,
    n_prev: FieldVar<F>,
) -> SnarkyResult<([FieldVar<F>; 2], ScaleRound<FieldVar<F>>)> {
    let (accs, (bits, ss)) = runner.compute(loc.clone(), |w| {
        let [x, y] = base.clone();
        let x = w.read_var(&x);
        let y = w.read_var(&y);
        let base = GroupAffine::<C>::new(x, y, false);

        let [x, y] = input;
        let x = w.read_var(&x);
        let y = w.read_var(&y);
        let i = GroupAffine::<C>::new(x, y, false);

        let mut limb = scalar.read(w);
        assert!(limb < 32, "should be 5 bits");
        let mut bits = Vec::with_capacity(5);
        for _ in 0..6 {
            bits.push((limb % 2) == 1);
            limb >>= 1;
        }
        bits.reverse();

        let points = std::iter::successors(Some(i), |i| {
            let o = base + *i + *i;
            Some(o)
        })
        .take(6)
        .collect::<Vec<_>>();
        let mut slopes = Vec::with_capacity(5);
        for i in 0..5 {
            let x = points[i].x - base.x;
            let y = base.y;
            let y = if bits[i] { y } else { -y };
            let y = points[i].y + y;
            slopes.push(y / x);
        }
        let accs: [_; 6] = points.try_into().unwrap();
        let accs = accs.map(|p| (p.x, p.y));
        let bits: [_; 5] = bits.try_into().unwrap();
        let bits = bits.map(|b| if b { F::one() } else { F::zero() });
        let ss: [_; 5] = slopes.try_into().unwrap();
        (accs, (bits, ss))
    })?;
    let accs: [(FieldVar<F>, FieldVar<F>); 6] = accs;
    let output = accs[5].clone();
    let accs = accs.to_vec();
    let bits: [FieldVar<F>; 5] = bits;
    let bits = bits.to_vec();
    let ss: [FieldVar<F>; 5] = ss;
    let ss = ss.to_vec();
    let n_next: FieldVar<F> = runner.compute(loc, |w| {
        let n_prev = w.read_var(&n_prev);
        let scalar = F::from(scalar.read(w));
        n_prev.pow([5_u64]) + scalar
    })?;
    let base = base.into();
    let constraint = ScaleRound {
        accs,
        bits,
        ss,
        base,
        n_prev,
        n_next,
    };
    Ok((output.into(), constraint))
}

///five bits limbs
fn split_in_limbs<F: PrimeField>(
    runner: &mut RunState<F>,
    loc: Cow<'static, str>,
    scalar: &FieldVar<F>,
) -> SnarkyResult<Limbs<F>> {
    runner.compute(loc, |w| {
        let scalar = w.read_var(scalar);
        let bytes = scalar.into_repr().to_bits_le();
        let limbs: Vec<u8> = bytes
            .chunks(5)
            .map(|l| {
                l.iter()
                    .rev()
                    .fold(0u8, |l, b| l + l + if *b { 1 } else { 0 })
            })
            .collect();
        let limbs: [u8; 51] = limbs.try_into().unwrap();
        limbs
    })
}

#[derive(Debug)]
struct Limbs<F: PrimeField>([u8; 51], PhantomData<F>);

impl<F: PrimeField> SnarkyType<F> for Limbs<F> {
    type Auxiliary = [u8; 51];

    type OutOfCircuit = [u8; 51];

    const SIZE_IN_FIELD_ELEMENTS: usize = 0;

    fn to_cvars(&self) -> (Vec<FieldVar<F>>, Self::Auxiliary) {
        (vec![], self.0)
    }

    fn from_cvars_unsafe(cvars: Vec<FieldVar<F>>, aux: Self::Auxiliary) -> Self {
        assert!(cvars.is_empty());
        Limbs(aux, PhantomData)
    }

    fn check(&self, _cs: &mut RunState<F>, _loc: Cow<'static, str>) -> SnarkyResult<()> {
        Ok(())
    }

    fn constraint_system_auxiliary() -> Self::Auxiliary {
        [0; 51]
    }

    fn value_to_field_elements(value: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary) {
        (vec![], *value)
    }

    fn value_of_field_elements(_fields: Vec<F>, aux: Self::Auxiliary) -> Self::OutOfCircuit {
        aux
    }
}
impl<F: PrimeField> From<Limbs<F>> for [Limb<F>; 51] {
    fn from(value: Limbs<F>) -> Self {
        value.0.map(|l| Limb(l, PhantomData))
    }
}

#[derive(Debug)]
pub struct Limb<F: PrimeField>(u8, PhantomData<F>);

impl<F: PrimeField> SnarkyType<F> for Limb<F> {
    type Auxiliary = u8;

    type OutOfCircuit = u8;

    const SIZE_IN_FIELD_ELEMENTS: usize = 0;

    fn to_cvars(&self) -> (Vec<FieldVar<F>>, Self::Auxiliary) {
        (vec![], self.0)
    }

    fn from_cvars_unsafe(cvars: Vec<FieldVar<F>>, aux: Self::Auxiliary) -> Self {
        assert!(cvars.is_empty());
        Limb(aux, PhantomData)
    }

    fn check(&self, _cs: &mut RunState<F>, _loc: Cow<'static, str>) -> SnarkyResult<()> {
        Ok(())
    }

    fn constraint_system_auxiliary() -> Self::Auxiliary {
        0
    }

    fn value_to_field_elements(value: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary) {
        (vec![], *value)
    }

    fn value_of_field_elements(_fields: Vec<F>, aux: Self::Auxiliary) -> Self::OutOfCircuit {
        aux
    }
}
