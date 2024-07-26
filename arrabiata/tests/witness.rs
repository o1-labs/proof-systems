use ark_ec::{short_weierstrass_jacobian::GroupAffine, ProjectiveCurve, SWModelParameters};
use ark_ff::{PrimeField, UniformRand};
use arrabiata::{
    interpreter::{self, ECAdditionSide, Instruction, InterpreterEnv},
    poseidon_3_60_0_5_5_fp, poseidon_3_60_0_5_5_fq,
    witness::Env,
    MAXIMUM_FIELD_SIZE_IN_BITS, POSEIDON_ROUNDS_FULL, POSEIDON_STATE_SIZE,
};
use mina_curves::pasta::{Fp, Fq, Pallas, ProjectivePallas, Vesta};
use mina_poseidon::{constants::SpongeConstants, permutation::poseidon_block_cipher};
use num_bigint::{BigInt, ToBigInt};
use o1_utils::FieldHelpers;
use poly_commitment::{commitment::CommitmentCurve, PolyComm};
use rand::{CryptoRng, RngCore};

// Used by the mina_poseidon library. Only for testing.
#[derive(Clone)]
pub struct PlonkSpongeConstants {}

impl SpongeConstants for PlonkSpongeConstants {
    const SPONGE_CAPACITY: usize = 1;
    const SPONGE_WIDTH: usize = POSEIDON_STATE_SIZE;
    const SPONGE_RATE: usize = 2;
    const PERM_ROUNDS_FULL: usize = POSEIDON_ROUNDS_FULL;
    const PERM_ROUNDS_PARTIAL: usize = 0;
    const PERM_HALF_ROUNDS_FULL: usize = 0;
    const PERM_SBOX: u32 = 5;
    const PERM_FULL_MDS: bool = true;
    const PERM_INITIAL_ARK: bool = false;
}

fn helper_generate_random_elliptic_curve_point<RNG, P: SWModelParameters>(
    rng: &mut RNG,
) -> GroupAffine<P>
where
    P::BaseField: PrimeField,
    RNG: RngCore + CryptoRng,
{
    let p1_x = P::BaseField::rand(rng);
    let mut p1: Option<GroupAffine<P>> = GroupAffine::<P>::get_point_from_x(p1_x, false);
    while p1.is_none() {
        let p1_x = P::BaseField::rand(rng);
        p1 = GroupAffine::<P>::get_point_from_x(p1_x, false);
    }
    let p1: GroupAffine<P> = p1.unwrap().scale_by_cofactor().into();
    p1
}

#[test]
fn test_unit_witness_poseidon_gadget() {
    let srs_log2_size = 6;
    let sponge: [BigInt; POSEIDON_STATE_SIZE] = std::array::from_fn(|_i| BigInt::from(42u64));
    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(
        srs_log2_size,
        BigInt::from(1u64),
        sponge.clone(),
        sponge.clone(),
    );
    (0..(POSEIDON_ROUNDS_FULL / 4)).for_each(|i| {
        interpreter::run_ivc(&mut env, Instruction::Poseidon(4 * i));
        env.reset();
    });
    let exp_output = {
        let mut state = sponge
            .clone()
            .to_vec()
            .iter()
            .map(|x| Fp::from_biguint(&x.to_biguint().unwrap()).unwrap())
            .collect::<Vec<_>>();
        poseidon_block_cipher::<Fp, PlonkSpongeConstants>(
            poseidon_3_60_0_5_5_fp::static_params(),
            &mut state,
        );
        state
            .iter()
            .map(|x| x.to_biguint().into())
            .collect::<Vec<_>>()
    };
    // Check correctness for current iteration
    assert_eq!(env.sponge_e1.to_vec(), exp_output);
    // Check the other sponge hasn't been modified
    assert_eq!(env.sponge_e2, sponge.clone());

    env.reset_for_next_iteration();
    env.current_iteration += 1;

    (0..(POSEIDON_ROUNDS_FULL / 4)).for_each(|i| {
        interpreter::run_ivc(&mut env, Instruction::Poseidon(4 * i));
        env.reset();
    });

    let exp_output = {
        let mut state = sponge
            .clone()
            .to_vec()
            .iter()
            .map(|x| Fq::from_biguint(&x.to_biguint().unwrap()).unwrap())
            .collect::<Vec<_>>();
        poseidon_block_cipher::<Fq, PlonkSpongeConstants>(
            poseidon_3_60_0_5_5_fq::static_params(),
            &mut state,
        );
        state
            .iter()
            .map(|x| x.to_biguint().into())
            .collect::<Vec<_>>()
    };
    // Check correctness for current iteration
    assert_eq!(env.sponge_e2.to_vec(), exp_output);
}

#[test]
fn test_unit_witness_elliptic_curve_addition() {
    let srs_log2_size = 6;
    let sponge_e1: [BigInt; POSEIDON_STATE_SIZE] = std::array::from_fn(|_i| BigInt::from(42u64));
    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(
        srs_log2_size,
        BigInt::from(1u64),
        sponge_e1.clone(),
        sponge_e1.clone(),
    );
    // If we are at iteration 0, we will compute the addition of points over
    // Pallas, whose scalar field is Fp.
    assert_eq!(env.current_iteration, 0);
    let (exp_x3, exp_y3) = {
        let res: Pallas =
            env.ivc_accumulator_e2[0].elems[0] + env.previous_commitments_e2[0].elems[0];
        let (x3, y3) = res.to_coordinates().unwrap();
        (
            x3.to_biguint().to_bigint().unwrap(),
            y3.to_biguint().to_bigint().unwrap(),
        )
    };
    interpreter::run_ivc(&mut env, Instruction::EllipticCurveAddition(0));
    assert_eq!(exp_x3, env.state[6], "The x coordinate is incorrect");
    assert_eq!(exp_y3, env.state[7], "The y coordinate is incorrect");

    env.reset();
    env.reset_for_next_iteration();
    env.current_iteration += 1;

    assert_eq!(env.current_iteration, 1);
    let (exp_x3, exp_y3) = {
        let res: Vesta =
            env.ivc_accumulator_e1[0].elems[0] + env.previous_commitments_e1[0].elems[0];
        let (x3, y3) = res.to_coordinates().unwrap();
        (
            x3.to_biguint().to_bigint().unwrap(),
            y3.to_biguint().to_bigint().unwrap(),
        )
    };
    interpreter::run_ivc(&mut env, Instruction::EllipticCurveAddition(0));
    assert_eq!(exp_x3, env.state[6], "The x coordinate is incorrect");
    assert_eq!(exp_y3, env.state[7], "The y coordinate is incorrect");

    env.reset();
    env.reset_for_next_iteration();
    env.current_iteration += 1;

    assert_eq!(env.current_iteration, 2);
    let (exp_x3, exp_y3) = {
        let res: Pallas =
            env.ivc_accumulator_e2[0].elems[0] + env.previous_commitments_e2[0].elems[0];
        let (x3, y3) = res.to_coordinates().unwrap();
        (
            x3.to_biguint().to_bigint().unwrap(),
            y3.to_biguint().to_bigint().unwrap(),
        )
    };
    interpreter::run_ivc(&mut env, Instruction::EllipticCurveAddition(0));

    assert_eq!(exp_x3, env.state[6], "The x coordinate is incorrect");
    assert_eq!(exp_y3, env.state[7], "The y coordinate is incorrect");
}

#[test]
fn test_witness_double_elliptic_curve_point() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let srs_log2_size = 6;
    let sponge_e1: [BigInt; POSEIDON_STATE_SIZE] = std::array::from_fn(|_i| BigInt::from(42u64));
    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(
        srs_log2_size,
        BigInt::from(1u64),
        sponge_e1.clone(),
        sponge_e1.clone(),
    );

    // Generate a random point
    let p1: Pallas = helper_generate_random_elliptic_curve_point(&mut rng);

    // Doubling in the environment
    let pos_x = env.allocate();
    let pos_y = env.allocate();
    let p1_x = env.write_column(pos_x, p1.x.to_biguint().into());
    let p1_y = env.write_column(pos_y, p1.y.to_biguint().into());
    let (res_x, res_y) = env.double_ec_point(pos_x, pos_y, p1_x, p1_y);

    let exp_res: Pallas = p1 + p1;
    let exp_x: BigInt = exp_res.x.to_biguint().into();
    let exp_y: BigInt = exp_res.y.to_biguint().into();

    assert_eq!(res_x, exp_x, "The x coordinate is incorrect");
    assert_eq!(res_y, exp_y, "The y coordinate is incorrect");
}

fn helper_elliptic_curve_scalar_multiplication<RNG>(r: BigInt, rng: &mut RNG)
where
    RNG: RngCore + CryptoRng,
{
    let srs_log2_size = 10;
    let sponge_e1: [BigInt; POSEIDON_STATE_SIZE] = std::array::from_fn(|_i| BigInt::from(42u64));
    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(
        srs_log2_size,
        BigInt::from(1u64),
        sponge_e1.clone(),
        sponge_e1.clone(),
    );

    let i_comm = 0;
    let p1: Pallas = helper_generate_random_elliptic_curve_point(rng);
    env.previous_commitments_e2[0] = PolyComm::new(vec![p1]);

    env.r = r.clone();

    // We only go up to the maximum bit field size.
    (0..MAXIMUM_FIELD_SIZE_IN_BITS).for_each(|bit_idx| {
        let instr = Instruction::EllipticCurveScaling(i_comm, bit_idx);
        env.current_instruction = instr;
        interpreter::run_ivc(&mut env, instr);
        env.reset();
    });

    let (res_x, res_y) = {
        let pos_x = env.allocate();
        let pos_y = env.allocate();
        let side = ECAdditionSide::Right;
        unsafe { env.load_temporary_accumulators(pos_x, pos_y, side) }
    };

    let p1_proj: ProjectivePallas = p1.into();
    let p1_r: Pallas = p1_proj.mul(r.clone().to_u64_digits().1).into();
    let exp_res: Pallas = p1_r + env.srs_e2.h;

    let exp_x: BigInt = exp_res.x.to_biguint().into();
    let exp_y: BigInt = exp_res.y.to_biguint().into();
    assert_eq!(res_x, exp_x, "The x coordinate is incorrect");
    assert_eq!(res_y, exp_y, "The y coordinate is incorrect");
}

#[test]
fn test_witness_elliptic_curve_scalar_multiplication_doubling() {
    let mut rng = o1_utils::tests::make_test_rng(None);

    // We start with doubling
    helper_elliptic_curve_scalar_multiplication(BigInt::from(2u64), &mut rng);

    // Special case of the identity
    helper_elliptic_curve_scalar_multiplication(BigInt::from(1u64), &mut rng);

    helper_elliptic_curve_scalar_multiplication(BigInt::from(3u64), &mut rng);

    // The answer to everything
    helper_elliptic_curve_scalar_multiplication(BigInt::from(42u64), &mut rng);

    // A random scalar
    let r: BigInt = Fp::rand(&mut rng).to_biguint().to_bigint().unwrap();
    helper_elliptic_curve_scalar_multiplication(r, &mut rng);
}
