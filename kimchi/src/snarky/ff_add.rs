use crate::{
    circuits::polynomials::foreign_field_add::witness::{compute_ffadd_values, FFOps},
    circuits::polynomials::foreign_field_common::{BigUintForeignFieldHelpers, LIMB_BITS},
    snarky::{
        constraint_system::{FFAdd, FFElement, FFModulus, KimchiConstraint},
        runner::Constraint,
        snarky_type::SnarkyType,
    },
    FieldVar, RunState, SnarkyResult,
};
use ark_ff::{BigInteger, BigInteger256, FpParameters, PrimeField};
use itertools::Itertools;
use num_bigint::BigUint;
use o1_utils::{self, foreign_field::ForeignFieldHelpers};
use std::borrow::Cow;

type ForeignElement<F, const N: usize> = o1_utils::ForeignElement<F, LIMB_BITS, N>;

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
    fn from_native(
        runner: &mut RunState<F>,
        loc: Cow<'static, str>,
        element: FieldVar<F>,
    ) -> SnarkyResult<Self> {
        let base = ForeignElement::<_, 3>::two_to_limb();
        let limbs: [FieldVar<F>; 3] = runner.compute(loc.clone(), |w| {
            let f = w.read_var(&element);
            let f = ForeignElement::<_, 3>::from_field(f);
            f.limbs
        })?;
        let [low, mid, high] = limbs;
        let x = element;
        let y = low.clone() + mid.scale(base) + high.scale(base.square());
        runner.assert_eq(Some("FFAdd native cast check".into()), loc, x, y)?;
        Ok(FFElement { low, mid, high })
    }
}

impl<F: PrimeField> SnarkyType<F> for FFElement<FieldVar<F>> {
    type Auxiliary = ();

    type OutOfCircuit = [F; 3];

    const SIZE_IN_FIELD_ELEMENTS: usize = 3;

    fn to_cvars(&self) -> (Vec<FieldVar<F>>, Self::Auxiliary) {
        (
            vec![self.low.clone(), self.mid.clone(), self.high.clone()],
            (),
        )
    }

    fn from_cvars_unsafe(cvars: Vec<FieldVar<F>>, _aux: Self::Auxiliary) -> Self {
        let [low, mid, high]: [_; 3] = cvars.try_into().unwrap();
        FFElement { low, mid, high }
    }

    fn check(&self, _cs: &mut RunState<F>, _loc: Cow<'static, str>) -> SnarkyResult<()> {
        todo!()
    }

    fn constraint_system_auxiliary() -> Self::Auxiliary {}

    fn value_to_field_elements(value: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary) {
        (value.to_vec(), ())
    }

    fn value_of_field_elements(fields: Vec<F>, _aux: Self::Auxiliary) -> Self::OutOfCircuit {
        fields.try_into().unwrap()
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
    let constraint1 = FFAdd {
        a,
        b,
        overflow,
        carry,
        modulus: modulus.clone(),
        sign: true,
        end: None,
    };
    // let constraint1 = Constraint::KimchiConstraint(KimchiConstraint::FFAdd(constraint));
    // runner.add_constraint(constraint, Some("FFAdd".into()), loc.clone())?;

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
    let two_to_limb =
        FieldVar::constant(ForeignElement::<F, 3>::two_to_limb()).seal(runner, loc.clone())?;
    let b = FFElement::new_const(FieldVar::zero(), FieldVar::zero(), two_to_limb);
    let [o0, o1, o2] = out;
    let end = FFElement::new(runner, loc.clone(), o0, o1, o2)?;
    let overflow = FieldVar::constant(F::one());
    // this will check that c + 2^264 - modulus < 2^264
    // and thus c < modulus
    let constraint2 = FFAdd {
        a: c.clone(),
        b,
        overflow,
        carry,
        modulus,
        sign: true,
        end: Some(end),
    };
    let constraint =
        Constraint::KimchiConstraint(KimchiConstraint::FFAdd(vec![constraint1, constraint2]));
    // runner.add_constraint(constraint1, Some("FFAdd".into()), loc.clone())?;
    runner.add_constraint(constraint, Some("FFAdd".into()), loc)?;

    Ok(c)
}
pub fn add_static<F, M>(
    runner: &mut RunState<F>,
    loc: Cow<'static, str>,
    a: FFElement<FieldVar<F>>,
    b: FFElement<FieldVar<F>>,
) -> SnarkyResult<FFElement<FieldVar<F>>>
where
    F: PrimeField,
    M: FpParameters<BigInt = BigInteger256>,
{
    let modulus = M::MODULUS;
    let mut modulus = modulus.to_bytes_le();
    assert!(modulus.len() <= 33);
    modulus.resize(33, 0);
    let foreign_modulus: Mod = modulus
        .into_iter()
        .chunks(11)
        .into_iter()
        .map(|c| c.collect::<Vec<_>>().try_into().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    add(runner, loc, a, b, foreign_modulus)
}

#[cfg(test)]
mod test {
    use crate::{
        circuits::expr::constraints::ExprOps,
        loc,
        snarky::{api::SnarkyCircuit, constraint_system::FFElement},
        FieldVar, RunState, SnarkyResult,
    };
    use ark_ff::{BigInteger, PrimeField, UniformRand};
    use mina_curves::pasta::{
        fields::fq::{Fq, FqParameters},
        Fp, Vesta, VestaParameters,
    };
    use mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi,
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };
    use num_bigint::BigUint;
    use num_traits::FromBytes;
    use poly_commitment::evaluation_proof::OpeningProof;
    use rand::thread_rng;

    use super::{add_static, ForeignElement};

    type BaseSponge = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
    type ScalarSponge = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;
    struct TestCircuit {}

    fn from_native_foreign(
        sys: &mut RunState<Fp>,
        elem: Option<Fq>,
    ) -> SnarkyResult<FFElement<FieldVar<Fp>>> {
        let elem: [_; 3] = sys.compute(loc!(), |w| {
            let bytes = elem.unwrap().0.to_bytes_le();
            let a = BigUint::from_le_bytes(&bytes);
            let a = ForeignElement::<_, 3>::from_biguint(a);
            a.limbs
        })?;
        let [low, mid, high] = elem;
        FFElement::new(sys, loc!(), low, mid, high)
    }
    fn to_native(limbs: [Fp; 3]) -> Fq {
        let [low, mid, high] = limbs.map(|x| Fq::from_le_bytes_mod_order(&x.0.to_bytes_le()));
        low + mid * Fq::two_to_limb() + high * Fq::two_to_2limb()
    }
    impl SnarkyCircuit for TestCircuit {
        type Curve = Vesta;
        type Proof = OpeningProof<Self::Curve>;

        type PrivateInput = (Fq, Fq);
        type PublicInput = ();
        type PublicOutput = FFElement<FieldVar<Fp>>;

        fn circuit(
            &self,
            sys: &mut RunState<Fp>,
            _public: Self::PublicInput,
            private: Option<&Self::PrivateInput>,
        ) -> SnarkyResult<Self::PublicOutput> {
            let a = from_native_foreign(sys, private.map(|p| p.0))?;
            let b = from_native_foreign(sys, private.map(|p| p.0))?;
            let c = add_static::<_, FqParameters>(sys, loc!(), a, b)?;

            Ok(c)
        }
    }

    #[test]
    fn snarky_ff_add() {
        // compile
        let test_circuit = TestCircuit {};

        let (mut prover_index, verifier_index) = test_circuit.compile_to_indexes().unwrap();

        // print ASM
        println!("{}", prover_index.asm());

        // prove
        {
            let mut rng = thread_rng();
            let private_input = (Fq::rand(&mut rng), Fq::rand(&mut rng));
            let sum = private_input.0 + private_input.1;

            let debug = true;
            let (proof, public_output) = prover_index
                .prove::<BaseSponge, ScalarSponge>((), private_input, debug)
                .unwrap();
            let circuit_result = to_native(*public_output);
            assert_eq!(circuit_result, sum);

            // verify proof
            verifier_index.verify::<BaseSponge, ScalarSponge>(proof, (), *public_output);
        }
    }
    /*#[test]
    #[should_panic]
    fn snarky_range_check_fail() {
        // compile
        let test_circuit = TestCircuit {};

        let (mut prover_index, _) = test_circuit.compile_to_indexes().unwrap();

        // print ASM
        println!("{}", prover_index.asm());

        // prove a bad execution
        {
            let private_input = Fp::from(0) - Fp::from(1);
            let debug = true;
            let (_proof, _public_output) = prover_index
                .prove::<BaseSponge, ScalarSponge>((), private_input, debug)
                .unwrap();
        }
    }*/
}
