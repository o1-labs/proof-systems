use super::{
    constraint_system::{FFAdd, FFElement, FFModulus, KimchiConstraint},
    runner::Constraint,
};
use crate::{
    circuits::polynomials::foreign_field_add::witness::{compute_ffadd_values, FFOps},
    FieldVar, RunState, SnarkyResult,
};
use ark_ff::PrimeField;
use num_bigint::BigUint;
use o1_utils::{
    foreign_field::{BigUintForeignFieldHelpers, ForeignFieldHelpers},
    ForeignElement,
};
use std::borrow::Cow;

impl<F: PrimeField> FFElement<FieldVar<F>> {
    ///limbs should be 88 bits, this method will add the range checks
    pub fn new(
        runner: &mut RunState<F>,
        loc: Cow<'static, str>,
        low: FieldVar<F>,
        mid: FieldVar<F>,
        high: FieldVar<F>,
    ) -> SnarkyResult<Self> {
        runner.range_check(loc, low.clone(), mid.clone(), high.clone())?;
        Ok(Self { low, mid, high })
    }
    fn new_const(low: FieldVar<F>, mid: FieldVar<F>, high: FieldVar<F>) -> Self {
        Self { low, mid, high }
    }
}
type Mod = [[u8; 11]; 3];
pub fn add<F: PrimeField>(
    runner: &mut RunState<F>,
    loc: Cow<'static, str>,
    a: FFElement<FieldVar<F>>,
    b: FFElement<FieldVar<F>>,
    foreign_modulus: Mod,
) -> SnarkyResult<FFElement<FieldVar<F>>> {
    //computing the addition
    let ((overflow, carry), c): ((_, _), [_; 3]) = runner.compute(loc.clone(), |w| {
        let a = [&a.low, &a.mid, &a.high];
        let a = a.map(|x| w.read_var(x));
        let b = [&b.low, &b.mid, &b.high];
        let [b0, b1, b2] = b.map(|x| w.read_var(&x));
        let b = [b0, b1, b2, F::zero()];

        let a = ForeignElement::new(a);
        let b = ForeignElement::new(b);
        let foreign_modulus = foreign_modulus.map(|x| F::from_le_bytes_mod_order(&x));
        let foreign_modulus = ForeignElement::new(foreign_modulus);

        let (output, _sign, ovf, carry) =
            compute_ffadd_values(&a, &b, FFOps::Add, &foreign_modulus);
        ((ovf, carry), output.limbs)
    })?;
    //creating and adding the constraint
    let modulus = FFModulus::new(foreign_modulus.map(|x| x.to_vec()));
    let constraint = FFAdd {
        a,
        b,
        overflow,
        carry,
        modulus: modulus.clone(),
        sign: true,
        end: None,
    };
    let constraint = Constraint::KimchiConstraint(KimchiConstraint::FFAdd(constraint));
    runner.add_constraint(constraint, Some("FFAdd".into()), loc.clone())?;

    //computing the extra addition used to check that the result is reduced
    let (carry, out): (_, [_; 3]) = runner.compute(loc.clone(), |w| {
        let c = c.clone().map(|x| w.read_var(&x));
        let c = ForeignElement::new(c);
        let max = ForeignElement::<F, 4>::from_biguint(BigUint::binary_modulus());

        let foreign_modulus = foreign_modulus.map(|x| F::from_le_bytes_mod_order(&x));
        let foreign_modulus = ForeignElement::new(foreign_modulus);

        let (output, _sign, _ovf, carry) =
            compute_ffadd_values(&c, &max, FFOps::Add, &foreign_modulus);
        (carry, output.limbs)
    })?;
    //2^264
    let [c0, c1, c2] = c;
    let c = FFElement::new(runner, loc.clone(), c0, c1, c2)?;
    let b = FFElement::new_const(
        FieldVar::zero(),
        FieldVar::zero(),
        FieldVar::constant(F::two_to_limb()),
    );
    let [o0, o1, o2] = out;
    let end = FFElement::new(runner, loc.clone(), o0, o1, o2)?;
    let overflow = FieldVar::constant(F::one());
    // this will check that c + 2^264 - modulus < 2^264
    // and thus c < modulus
    let constraint = FFAdd {
        a: c.clone(),
        b,
        overflow,
        carry,
        modulus,
        sign: true,
        end: Some(end),
    };
    let constraint = Constraint::KimchiConstraint(KimchiConstraint::FFAdd(constraint));
    runner.add_constraint(constraint, Some("FFAdd".into()), loc)?;

    Ok(c)
}
