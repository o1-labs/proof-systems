use ark_ec::{AffineRepr, Group};
use ark_ff::{PrimeField, UniformRand};
use arrabbiata::{
    curve::PlonkSpongeConstants,
    interpreter::{self, Instruction, InterpreterEnv},
    poseidon_3_60_0_5_5_fp,
    setup::IndexedRelation,
    witness::Env,
    MAXIMUM_FIELD_SIZE_IN_BITS, MIN_SRS_LOG2_SIZE,
};
use mina_curves::pasta::{Fp, Fq, Pallas, ProjectivePallas, Vesta};
use mina_poseidon::{constants::SpongeConstants, permutation::poseidon_block_cipher};
use num_bigint::{BigInt, ToBigInt};
use o1_utils::FieldHelpers;
use poly_commitment::{commitment::CommitmentCurve, PolyComm};
use rand::{CryptoRng, RngCore};

#[test]
fn test_unit_witness_poseidon_permutation_gadget_one_full_hash() {
    // Expected output:
    // 13562506435502224548799089445428941958058503946524561166818119397766682137724
    // 27423099486669760867028539664936216880884888701599404075691059826529320129892
    // 736058628407775696076653472820678709906041621699240400715815852096937303940
    let indexed_relation = IndexedRelation::new(MIN_SRS_LOG2_SIZE);

    let sponge: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH] =
        indexed_relation.initial_sponge.clone();

    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(BigInt::from(1u64), indexed_relation);

    env.current_instruction = Instruction::PoseidonFullRound(0);

    (0..(PlonkSpongeConstants::PERM_ROUNDS_FULL / 5)).for_each(|i| {
        interpreter::run_ivc(&mut env, Instruction::PoseidonFullRound(5 * i));
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

    // Number of rows used by one full hash
    assert_eq!(env.current_row, 12);
}

#[test]
fn test_unit_witness_poseidon_with_absorb_one_full_hash() {
    let indexed_relation: IndexedRelation<Fp, Fq, Vesta, Pallas> =
        IndexedRelation::new(MIN_SRS_LOG2_SIZE);

    let sponge: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH] =
        indexed_relation.initial_sponge.clone();

    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(BigInt::from(1u64), indexed_relation);

    env.current_instruction = Instruction::PoseidonSpongeAbsorb;
    interpreter::run_ivc(&mut env, Instruction::PoseidonSpongeAbsorb);
    env.reset();

    (0..(PlonkSpongeConstants::PERM_ROUNDS_FULL / 5)).for_each(|i| {
        interpreter::run_ivc(&mut env, Instruction::PoseidonFullRound(5 * i));
        env.reset();
    });

    let exp_output = {
        let mut state = sponge
            .clone()
            .to_vec()
            .iter()
            .map(|x| Fp::from_biguint(&x.to_biguint().unwrap()).unwrap())
            .collect::<Vec<_>>();
        // Absorbing the first commitment
        let (pt_x, pt_y) = env.program_e2.accumulated_committed_state[0]
            .get_first_chunk()
            .to_coordinates()
            .unwrap();
        state[1] += pt_x;
        state[2] += pt_y;

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
    let indexed_relation: IndexedRelation<Fp, Fq, Vesta, Pallas> =
        IndexedRelation::new(MIN_SRS_LOG2_SIZE);

    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(BigInt::from(1u64), indexed_relation);

    let instr = Instruction::EllipticCurveAddition(0);
    env.current_instruction = instr;

    // If we are at iteration 0, we will compute the addition of points over
    // Pallas, whose scalar field is Fp.
    assert_eq!(env.current_iteration, 0);
    let (exp_x3, exp_y3) = {
        let res: Pallas = (env.program_e2.accumulated_committed_state[0].get_first_chunk()
            + env.program_e2.previous_committed_state[0].get_first_chunk())
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
        let res: Vesta = (env.program_e1.accumulated_committed_state[0].get_first_chunk()
            + env.program_e1.previous_committed_state[0].get_first_chunk())
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
        let res: Pallas = (env.program_e2.accumulated_committed_state[0].get_first_chunk()
            + env.program_e2.previous_committed_state[0].get_first_chunk())
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
    let indexed_relation: IndexedRelation<Fp, Fq, Vesta, Pallas> =
        IndexedRelation::new(MIN_SRS_LOG2_SIZE);

    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(BigInt::from(1u64), indexed_relation);

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
    let mut indexed_relation = IndexedRelation::new(MIN_SRS_LOG2_SIZE);
    // FIXME: For test purposes, to get a deterministic result, changing the
    // initial sponge state. The challenge in the circuit will be the first
    // element of the state.
    indexed_relation.initial_sponge = core::array::from_fn(|_i| r.clone());

    let mut env = Env::<Fp, Fq, Vesta, Pallas>::new(BigInt::from(1u64), indexed_relation);

    let i_comm = 0;
    let p1: Pallas = {
        let x = Fq::rand(rng);
        Pallas::generator().mul_bigint(x.into_bigint()).into()
    };
    env.program_e2.previous_committed_state[0] = PolyComm::new(vec![p1]);

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
    let exp_res: Pallas = (p1_r + env.indexed_relation.srs_e2.h).into();

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

#[test]
fn test_regression_witness_structure_sizeof() {
    // Keeping track of the size (in bytes) of the witness environment
    // structure. It is for optimisation later.
    // It will probably be annoying to update this test every time we update the
    // structure of the environment, but it will be useful to remind us to keep
    // thinking about the memory efficiency of the codebase.
    let size = std::mem::size_of::<Env<Fp, Fq, Vesta, Pallas>>();
    println!("Current size of Env structure: {}", size);
    assert_eq!(size, 5888, "The witness environment structure changed")
}
