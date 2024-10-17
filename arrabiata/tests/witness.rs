use ark_ec::{AffineRepr, Group};
use ark_ff::{PrimeField, UniformRand};
use arrabiata::{
    curve::PlonkSpongeConstants,
    interpreter::{self, Instruction, InterpreterEnv},
    poseidon_3_60_0_5_5_fp,
    witness::Env,
    MAXIMUM_FIELD_SIZE_IN_BITS,
};
use mina_curves::pasta::{Fp, Fq, Pallas, ProjectivePallas, Vesta};
use mina_poseidon::{constants::SpongeConstants, permutation::poseidon_block_cipher};
use num_bigint::{BigInt, ToBigInt};
use o1_utils::FieldHelpers;
use poly_commitment::{commitment::CommitmentCurve, PolyComm};
use rand::{CryptoRng, RngCore};

#[test]
fn test_unit_witness_poseidon_next_row_gadget_one_full_hash() {
    let srs_log2_size = 6;
    let sponge: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH] =
        std::array::from_fn(|_i| BigInt::from(42u64));
    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(
        srs_log2_size,
        BigInt::from(1u64),
        sponge.clone(),
        sponge.clone(),
    );

    env.current_instruction = Instruction::Poseidon(0);

    (0..(PlonkSpongeConstants::PERM_ROUNDS_FULL / 5)).for_each(|i| {
        interpreter::run_ivc(&mut env, Instruction::Poseidon(5 * i));
        env.reset();
    });
    let exp_output = {
        let mut state = sponge
            .clone()
            .to_vec()
            .iter()
            .map(|x| Fp::from_biguint(&x.to_biguint().unwrap()).unwrap())
            .collect::<Vec<_>>();
        state[0] += env.srs_e2.h.x;
        state[1] += env.srs_e2.h.y;
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

    // Number of rows used by one full hash
    assert_eq!(env.current_row, 13);
}

#[test]
fn test_unit_witness_elliptic_curve_addition() {
    let srs_log2_size = 6;
    let sponge_e1: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH] =
        std::array::from_fn(|_i| BigInt::from(42u64));
    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(
        srs_log2_size,
        BigInt::from(1u64),
        sponge_e1.clone(),
        sponge_e1.clone(),
    );

    let instr = Instruction::EllipticCurveAddition(0);
    env.current_instruction = instr;

    // If we are at iteration 0, we will compute the addition of points over
    // Pallas, whose scalar field is Fp.
    assert_eq!(env.current_iteration, 0);
    let (exp_x3, exp_y3) = {
        let res: Pallas = (env.ivc_accumulator_e2[0].get_first_chunk()
            + env.previous_commitments_e2[0].get_first_chunk())
        .into();
        let (x3, y3) = res.to_coordinates().unwrap();
        (
            x3.to_biguint().to_bigint().unwrap(),
            y3.to_biguint().to_bigint().unwrap(),
        )
    };
    interpreter::run_ivc(&mut env, instr);
    assert_eq!(exp_x3, env.state[6], "The x coordinate is incorrect");
    assert_eq!(exp_y3, env.state[7], "The y coordinate is incorrect");

    env.reset();
    env.reset_for_next_iteration();
    env.current_instruction = instr;
    env.current_iteration += 1;

    assert_eq!(env.current_iteration, 1);
    let (exp_x3, exp_y3) = {
        let res: Vesta = (env.ivc_accumulator_e1[0].get_first_chunk()
            + env.previous_commitments_e1[0].get_first_chunk())
        .into();
        let (x3, y3) = res.to_coordinates().unwrap();
        (
            x3.to_biguint().to_bigint().unwrap(),
            y3.to_biguint().to_bigint().unwrap(),
        )
    };
    interpreter::run_ivc(&mut env, instr);
    assert_eq!(exp_x3, env.state[6], "The x coordinate is incorrect");
    assert_eq!(exp_y3, env.state[7], "The y coordinate is incorrect");

    env.reset();
    env.reset_for_next_iteration();
    env.current_instruction = instr;
    env.current_iteration += 1;

    assert_eq!(env.current_iteration, 2);
    let (exp_x3, exp_y3) = {
        let res: Pallas = (env.ivc_accumulator_e2[0].get_first_chunk()
            + env.previous_commitments_e2[0].get_first_chunk())
        .into();
        let (x3, y3) = res.to_coordinates().unwrap();
        (
            x3.to_biguint().to_bigint().unwrap(),
            y3.to_biguint().to_bigint().unwrap(),
        )
    };
    interpreter::run_ivc(&mut env, instr);

    assert_eq!(exp_x3, env.state[6], "The x coordinate is incorrect");
    assert_eq!(exp_y3, env.state[7], "The y coordinate is incorrect");
}

#[test]
fn test_witness_double_elliptic_curve_point() {
    let mut rng = o1_utils::tests::make_test_rng(None);
    let srs_log2_size = 6;
    let sponge_e1: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH] =
        std::array::from_fn(|_i| BigInt::from(42u64));
    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(
        srs_log2_size,
        BigInt::from(1u64),
        sponge_e1.clone(),
        sponge_e1.clone(),
    );

    env.current_instruction = Instruction::EllipticCurveAddition(0);

    // Generate a random point
    let p1: Pallas = {
        let x = Fq::rand(&mut rng);
        Pallas::generator().mul_bigint(x.into_bigint()).into()
    };

    // Doubling in the environment
    let pos_x = env.allocate();
    let pos_y = env.allocate();
    let p1_x = env.write_column(pos_x, p1.x.to_biguint().into());
    let p1_y = env.write_column(pos_y, p1.y.to_biguint().into());
    let (res_x, res_y) = env.double_ec_point(pos_x, pos_y, p1_x, p1_y);

    let exp_res: Pallas = (p1 + p1).into();
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
    let sponge_e1: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH] =
        std::array::from_fn(|_i| r.clone());
    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(
        srs_log2_size,
        BigInt::from(1u64),
        sponge_e1.clone(),
        sponge_e1.clone(),
    );

    let i_comm = 0;
    let p1: Pallas = {
        let x = Fq::rand(rng);
        Pallas::generator().mul_bigint(x.into_bigint()).into()
    };
    env.previous_commitments_e2[0] = PolyComm::new(vec![p1]);

    // We only go up to the maximum bit field size.
    (0..MAXIMUM_FIELD_SIZE_IN_BITS).for_each(|bit_idx| {
        let instr = Instruction::EllipticCurveScaling(i_comm, bit_idx);
        env.current_instruction = instr;
        interpreter::run_ivc(&mut env, instr);
        env.reset();
    });

    let res_x: BigInt = env.state[0].clone();
    let res_y: BigInt = env.state[1].clone();

    let p1_proj: ProjectivePallas = p1.into();
    // @volhovm TODO check if mul_bigint is what was intended
    let p1_r: Pallas = p1_proj.mul_bigint(r.clone().to_u64_digits().1).into();
    let exp_res: Pallas = (p1_r + env.srs_e2.h).into();

    let exp_x: BigInt = exp_res.x.to_biguint().into();
    let exp_y: BigInt = exp_res.y.to_biguint().into();
    assert_eq!(res_x, exp_x, "The x coordinate is incorrect");
    assert_eq!(res_y, exp_y, "The y coordinate is incorrect");
}

#[test]
fn test_witness_elliptic_curve_scalar_multiplication() {
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
