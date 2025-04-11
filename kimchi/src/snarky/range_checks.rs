use super::{constraint_system::KimchiConstraint, runner::Constraint};
use crate::{circuits::polynomial::COLUMNS, FieldVar, RunState, SnarkyResult};
use ark_ff::{BigInteger, PrimeField};
use itertools::Itertools;
use std::borrow::Cow;

///creates a field elements from the next B bits
fn parse_limb<F: PrimeField, const B: usize>(bits: impl Iterator<Item = bool>) -> F {
    assert!(B <= 16);
    let mut l = 0_u16;
    let bits = bits.take(B).collect_vec();
    let mut bits = bits.into_iter().rev();
    for _ in 0..B {
        let b = bits.next().unwrap();
        let b = if b { 1 } else { 0 };
        l = l + l + b;
    }
    F::from(l)
}

///extracts N limbs of B bits each from the iterator provided
fn parse_limbs<F: PrimeField, const B: usize, const N: usize>(
    mut bits: impl Iterator<Item = bool>,
) -> [F; N] {
    [(); N].map(|_| parse_limb::<F, B>(bits.by_ref()))
}

///for v0 and v1
struct RangeCheckLimbs1<F: PrimeField> {
    crumbs: [F; 8],
    limbs: [F; 6],
}

impl<F: PrimeField> RangeCheckLimbs1<F> {
    ///extracts the limbs needed for range check from the bits of f
    fn parse(f: F) -> Self {
        let mut bits = f.into_bigint().to_bits_le().into_iter();
        let crumbs = parse_limbs::<F, 2, 8>(bits.by_ref());
        let limbs = parse_limbs::<F, 12, 6>(bits);
        Self { crumbs, limbs }
    }
    ///produces limbs and crumbs with the expected endianness
    fn into_repr(mut self) -> ([F; 6], [F; 8]) {
        self.crumbs.reverse();
        self.limbs.reverse();
        let Self { crumbs, limbs } = self;
        (limbs, crumbs)
    }
}

///for v2
struct RangeCheckLimbs2<F: PrimeField> {
    crumbs_low: [F; 19],
    limbs: [F; 4],
    crumbs_high: [F; 1],
}

impl<F: PrimeField> RangeCheckLimbs2<F> {
    ///extracts the limbs needed for range check from the bits of f
    fn parse(f: F) -> Self {
        let mut bits = f.into_bigint().to_bits_le().into_iter();
        let crumbs_low = parse_limbs::<F, 2, 19>(bits.by_ref());
        let limbs = parse_limbs::<F, 12, 4>(bits.by_ref());
        let crumbs_high = parse_limbs::<F, 2, 1>(bits);
        Self {
            crumbs_low,
            limbs,
            crumbs_high,
        }
    }
    ///produces limbs and crumbs with the expected endianness
    fn into_repr(mut self) -> ([F; 1], [F; 4], [F; 19]) {
        self.crumbs_high.reverse();
        self.limbs.reverse();
        self.crumbs_low.reverse();
        let Self {
            crumbs_low,
            limbs,
            crumbs_high,
        } = self;
        (crumbs_high, limbs, crumbs_low)
    }
}

pub fn range_check<F: PrimeField>(
    runner: &mut RunState<F>,
    loc: Cow<'static, str>,
    v0: FieldVar<F>,
    v1: FieldVar<F>,
    v2: FieldVar<F>,
) -> SnarkyResult<()> {
    let v0_limbs: ([FieldVar<F>; 6], [FieldVar<F>; 8]) = runner.compute(loc.clone(), |w| {
        let v = w.read_var(&v0);
        let limbs = RangeCheckLimbs1::parse(v);
        limbs.into_repr()
    })?;
    let v0p0 = v0_limbs.0[0].clone();
    let v0p1 = v0_limbs.0[1].clone();
    let r0 = [v0]
        .into_iter()
        .chain(v0_limbs.0)
        .chain(v0_limbs.1)
        .collect_vec();
    let r0: [FieldVar<F>; COLUMNS] = r0.try_into().unwrap();

    let v1_limbs: ([FieldVar<F>; 6], [FieldVar<F>; 8]) = runner.compute(loc.clone(), |w| {
        let v = w.read_var(&v1);
        let limbs = RangeCheckLimbs1::parse(v);
        limbs.into_repr()
    })?;
    let v1p0 = v1_limbs.0[0].clone();
    let v1p1 = v1_limbs.0[1].clone();
    let r1 = [v1]
        .into_iter()
        .chain(v1_limbs.0)
        .chain(v1_limbs.1)
        .collect_vec();

    type Limbs<F, const N: usize> = [FieldVar<F>; N];
    let r1: [FieldVar<F>; COLUMNS] = r1.try_into().unwrap();
    let v2_limbs: ((Limbs<F, 1>, Limbs<F, 4>), Limbs<F, 19>) =
        runner.compute(loc.clone(), |w| {
            let v = w.read_var(&v2);
            let limbs = RangeCheckLimbs2::parse(v);
            let (a, b, c) = limbs.into_repr();
            ((a, b), c)
        })?;
    let ((v2_crumb_high, v2_limb), v2_crumb_low) = v2_limbs;
    let mut v2_crumb_high = v2_crumb_high.into_iter();
    let mut v2_crumb_low = v2_crumb_low.into_iter();

    let r2 = [v2]
        .into_iter()
        .chain([FieldVar::zero()])
        .chain(v2_crumb_high.next())
        .chain(v2_limb)
        .chain(v2_crumb_low.by_ref().take(8))
        .collect_vec();

    let r2: [FieldVar<F>; COLUMNS] = r2.try_into().unwrap();

    let first_3 = v2_crumb_low.by_ref().take(3).collect_vec();
    let r3 = first_3
        .into_iter()
        .chain([v0p0, v0p1, v1p0, v1p1])
        .chain(v2_crumb_low.take(8))
        .collect_vec();
    let r3: [FieldVar<F>; COLUMNS] = r3.try_into().unwrap();

    let rows = [r0, r1, r2, r3].map(|r| r.to_vec()).to_vec();

    let constraint = Constraint::KimchiConstraint(KimchiConstraint::RangeCheck(rows));
    runner.add_constraint(constraint, Some("Range check".into()), loc)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::{
        circuits::expr::constraints::ExprOps, loc, snarky::api::SnarkyCircuit, FieldVar, RunState,
        SnarkyResult,
    };
    use mina_curves::pasta::{Fp, Vesta, VestaParameters};
    use mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi,
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };
    use poly_commitment::ipa::OpeningProof;

    type BaseSponge = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
    type ScalarSponge = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;
    struct TestCircuit {}

    impl SnarkyCircuit for TestCircuit {
        type Curve = Vesta;
        type Proof = OpeningProof<Self::Curve>;

        type PrivateInput = Fp;
        type PublicInput = ();
        type PublicOutput = ();

        fn circuit(
            &self,
            sys: &mut RunState<Fp>,
            _public: Self::PublicInput,
            private: Option<&Self::PrivateInput>,
        ) -> SnarkyResult<Self::PublicOutput> {
            let v: FieldVar<Fp> = sys.compute(loc!(), |_| *private.unwrap())?;

            sys.range_check(loc!(), v.clone(), v.clone(), v)?;

            Ok(())
        }
    }

    #[test]
    fn snarky_range_check() {
        // compile
        let test_circuit = TestCircuit {};

        let (mut prover_index, verifier_index) = test_circuit.compile_to_indexes().unwrap();

        let mut rng = o1_utils::tests::make_test_rng(None);

        use rand::Rng;
        // prove
        {
            let private_input: Fp = Fp::from(rng.gen::<u64>());

            let debug = true;
            let (proof, _public_output) = prover_index
                .prove::<BaseSponge, ScalarSponge>((), private_input, debug)
                .unwrap();

            // verify proof
            verifier_index.verify::<BaseSponge, ScalarSponge>(proof, (), ());
        }

        // prove a different execution
        {
            let private_input = Fp::from(2).pow(88) - Fp::from(1);
            let debug = true;
            let (proof, _public_output) = prover_index
                .prove::<BaseSponge, ScalarSponge>((), private_input, debug)
                .unwrap();

            // verify proof
            verifier_index.verify::<BaseSponge, ScalarSponge>(proof, (), ());
        }
    }
    #[test]
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
    }
}
