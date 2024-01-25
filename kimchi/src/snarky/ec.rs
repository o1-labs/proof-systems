//! Functions associated to the EC addition and scaling.

use super::constraint_system::EcAddCompleteInput;
use crate::{
    snarky::{
        constraint_system::KimchiConstraint,
        prelude::{FieldVar, RunState},
        runner::Constraint,
    },
    SnarkyResult,
};
use ark_ec::{short_weierstrass_jacobian::GroupAffine, SWModelParameters};
use ark_ff::PrimeField;
use std::borrow::Cow;

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
            } else {
                if x1 == x2 {
                    y_diff.inverse().unwrap()
                } else {
                    F::zero()
                }
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
