use super::framework::TestFramework;
use crate::circuits::gate::CircuitGateResult;
use crate::circuits::polynomials::generic::GenericGateSpec;
use crate::prover_index::ProverIndex;
use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, CircuitGateError, Connect, GateType},
        polynomial::COLUMNS,
        polynomials::{
            foreign_field_add::witness::{self, FFOps},
            range_check::{self, witness::extend_multi},
        },
        wires::Wire,
    },
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
};
use ark_ec::AffineCurve;
use ark_ff::{One, PrimeField, SquareRootField, Zero};
use ark_poly::EvaluationDomain;
use commitment_dlog::srs::{endos, SRS};
use mina_curves::pasta::{Fp, Fq, Pallas, PallasParameters, Vesta, VestaParameters};
use mina_poseidon::FqSponge;
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use num_bigint::{BigUint, RandBigInt};
use num_traits::FromPrimitive;
use o1_utils::{
    foreign_field::{ForeignElement, HI, LO, MI, TWO_TO_LIMB},
    FieldHelpers, Two,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::array;
use std::sync::Arc;
type PallasField = <Pallas as AffineCurve>::BaseField;
type VestaField = <Vesta as AffineCurve>::BaseField;

type SpongeParams = PlonkSpongeConstantsKimchi;
type VestaBaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type VestaScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
type PallasBaseSponge = DefaultFqSponge<PallasParameters, SpongeParams>;
type PallasScalarSponge = DefaultFrSponge<Fq, SpongeParams>;

type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

// The secp256k1 base field modulus
fn secp256k1_modulus() -> BigUint {
    BigUint::from_bytes_be(&secp256k1::constants::FIELD_SIZE)
}

// Maximum value in the foreign field of secp256k1
fn secp256k1_max() -> BigUint {
    secp256k1_modulus() - BigUint::from(1u32)
}

const RNG_SEED: [u8; 32] = [
    0, 131, 43, 175, 229, 252, 206, 26, 67, 193, 86, 160, 1, 90, 131, 86, 168, 4, 95, 50, 48, 9,
    192, 13, 250, 215, 172, 130, 24, 164, 162, 221,
];

// A value that produces a negative low carry when added to itself
static OVF_NEG_LO: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// A value that produces a negative middle carry when added to itself
static OVF_NEG_MI: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2E,
];

// A value that produces overflow but the high limb of the result is smaller than the high limb of the modulus
static OVF_LESS_HI_LEFT: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2E,
];
static OVF_LESS_HI_RIGHT: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0xD1,
];

// A value that produces two negative carries when added together with [OVF_ZERO_MI_NEG_LO]
static OVF_NEG_BOTH: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// A value that produces two negative carries when added to itself with a middle limb that is all zeros
static OVF_ZERO_MI_NEG_LO: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// All 0x55 bytes meaning [0101 0101]
static TIC: &[u8] = &[
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
];

// Prefix 0xAA bytes but fits in foreign field (suffix is zeros)
static TOC: &[u8] = &[
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Bytestring that produces carry in low limb when added to TIC
static TOC_LO: &[u8] = &[
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xA9, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Bytestring that produces carry in mid limb when added to TIC
static TOC_MI: &[u8] = &[
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xA9, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Bytestring that produces carry in low and mid limb when added to TIC
static TOC_TWO: &[u8] = &[
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xA9, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xA9, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
];

//  Bottom half of the secp256k1 base field modulus
fn secp256k1_modulus_bottom() -> BigUint {
    BigUint::from_bytes_be(&secp256k1::constants::FIELD_SIZE[16..])
}

// Top half of the secp256k1 base field modulus
fn secp256k1_modulus_top() -> BigUint {
    let bytes = [&secp256k1::constants::FIELD_SIZE[0..16], &[0; 16]].concat();
    BigUint::from_bytes_be(&bytes)
}

// returns the maximum value for a field of modulus size
fn field_max(modulus: BigUint) -> BigUint {
    modulus - 1u32
}

// Value that performs a + - 1 low carry when added to [MAX]
static NULL_CARRY_LO: &[u8] = &[0x01, 0x00, 0x00, 0x03, 0xD2];

// Value that performs a + - 1 middle carry when added to [MAX]
static NULL_CARRY_MI: &[u8] = &[
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

// Value that performs two + - 1 carries when added to [MAX]
static NULL_CARRY_BOTH: &[u8] = &[
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0xD2,
];

impl<F: PrimeField + SquareRootField> CircuitGate<F> {
    /// Check if a given circuit gate is a given foreign field operation
    pub fn check_ffadd_sign(&self, sign: FFOps) -> Result<(), String> {
        if self.typ != GateType::ForeignFieldAdd {
            return Err("Gate is not a foreign field add gate".to_string());
        }
        match sign {
            FFOps::Add => {
                if self.coeffs[3] != F::one() {
                    return Err("Gate is not performing addition".to_string());
                }
            }
            FFOps::Sub => {
                if self.coeffs[3] != -F::one() {
                    return Err("Gate is not performing subtraction".to_string());
                }
            }
        }
        Ok(())
    }
}

// Creates a circuit including the public input, chain of additions only
// Inputs
//  operations
//  foreign field modulus
// Outputs tuple (next_row, circuit_gates) where
//  next_row      - next row after this gate
//  circuit_gates - vector of circuit gates comprising this gate
fn short_circuit<F: PrimeField + SquareRootField>(
    opcodes: &[FFOps],
    foreign_field_modulus: &BigUint,
) -> (usize, Vec<CircuitGate<F>>) {
    // [0]           -> Public input row to store the value 1
    // {
    //  [1+i] ->     -> 1 ForeignFieldAdd row
    // } * num times
    // [n+1]         -> 1 ForeignFieldAdd row (this is where the final result goes)
    // [n+2]         -> 1 Zero row for bound result
    let mut gates = vec![CircuitGate::<F>::create_generic_gadget(
        Wire::for_row(0),
        GenericGateSpec::Pub,
        None,
    )];
    let mut curr_row = 1;
    CircuitGate::<F>::extend_chain_ffadd(
        &mut gates,
        0,
        &mut curr_row,
        opcodes,
        foreign_field_modulus,
    );
    (curr_row, gates)
}

// Creates a circuit including the public input, chain of additions and rangechecks for all of the involved values
// Inputs
//  operations
//  foreign field modulus
// Outputs tuple (next_row, circuit_gates) where
//  next_row      - next row after this gate
//  circuit_gates - vector of circuit gates comprising this gate
fn full_circuit<F: PrimeField + SquareRootField>(
    opcodes: &[FFOps],
    foreign_field_modulus: &BigUint,
) -> (usize, Vec<CircuitGate<F>>) {
    // [0]           -> Public input row to store the value 1
    // {
    //  [1+i] ->     -> 1 ForeignFieldAdd row
    // } * num times
    // [n+1]         -> 1 ForeignFieldAdd row (this is where the final result goes)
    // [n+2]         -> 1 Zero row for bound result
    // -----
    // [n+3..n+6]    -> 1 Multi RangeCheck for first left input
    // {
    //  [n+ 7+8i...n+10+8i]  -> 1 Multi RangeCheck for right input
    //  [n+11+8i...n+14+8i]  -> 1 Multi RangeCheck for result
    // } * num times
    // [9n+7...9n+10] -> 1 Multi RangeCheck for bound
    let (mut next_row, mut gates) = short_circuit(opcodes, foreign_field_modulus);

    let num = opcodes.len();

    // RANGE CHECKS
    // Add rangechecks for inputs, results, and final bound
    CircuitGate::extend_multi_range_check(&mut gates, &mut next_row); // left input
    for _ in 0..num {
        for _ in 0..2 {
            // right input and result
            CircuitGate::extend_multi_range_check(&mut gates, &mut next_row);
        }
    }
    // bound
    CircuitGate::extend_multi_range_check(&mut gates, &mut next_row);

    // WIRING
    // Connect the num FFAdd gates with the range-check cells
    for i in 0..num {
        let ffadd_row = i + 1;
        let left_row = num + 3 + 8 * i;
        let right_row = num + 7 + 8 * i;
        let out_row = num + 11 + 8 * i;

        // Copy left_input_lo -> Curr(0)
        gates.connect_cell_pair((left_row, 0), (ffadd_row, 0));
        // Copy left_input_mi -> Curr(1)
        gates.connect_cell_pair((left_row + 1, 0), (ffadd_row, 1));
        // Copy left_input_hi -> Curr(2)
        gates.connect_cell_pair((left_row + 2, 0), (ffadd_row, 2));

        // Copy right_input_lo -> Curr(3)
        gates.connect_cell_pair((right_row, 0), (ffadd_row, 3));
        // Copy right_input_mi -> Curr(4)
        gates.connect_cell_pair((right_row + 1, 0), (ffadd_row, 4));
        // Copy right_input_hi -> Curr(5)
        gates.connect_cell_pair((right_row + 2, 0), (ffadd_row, 5));

        // Copy result_lo -> Next(0)
        gates.connect_cell_pair((out_row, 0), (ffadd_row + 1, 0));
        // Copy result_mi -> Next(1)
        gates.connect_cell_pair((out_row + 1, 0), (ffadd_row + 1, 1));
        // Copy result_hi -> Next(2)
        gates.connect_cell_pair((out_row + 2, 0), (ffadd_row + 1, 2));
    }
    // Connect final bound gate to range-check cells
    let final_row = num + 2;
    let bound_row = 9 * num + 7;
    // Copy bound_lo -> Next(3)
    gates.connect_cell_pair((bound_row, 0), (final_row, 0));
    // Copy bound_mi -> Next(4)
    gates.connect_cell_pair((bound_row + 1, 0), (final_row, 1));
    // Copy bound_hi -> Next(5)
    gates.connect_cell_pair((bound_row + 2, 0), (final_row, 2));

    (next_row, gates)
}

// Creates the witness with the public input for FFAdd containing the 1 value
fn short_witness<F: PrimeField>(
    inputs: &Vec<BigUint>,
    opcodes: &[FFOps],
    modulus: BigUint,
) -> [Vec<F>; COLUMNS] {
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 1]);
    witness[0][0] = F::one();
    let add_witness = witness::create_chain::<F>(inputs, opcodes, modulus);
    for col in 0..COLUMNS {
        witness[col].extend(add_witness[col].iter());
    }
    witness
}

// Creates a long witness including the chain of additions and rangechecks for all of the involved values
// inputs: list of all inputs to the chain of additions/subtractions
// opcode: true for addition, false for subtraction
// modulus: modulus of the foreign field
fn long_witness<F: PrimeField>(
    inputs: &Vec<BigUint>,
    opcodes: &[FFOps],
    modulus: BigUint,
) -> [Vec<F>; COLUMNS] {
    let mut witness: [Vec<F>; COLUMNS] = short_witness(inputs, opcodes, modulus);

    let num = inputs.len() - 1; // number of chained additions

    // Create multi-range-check witness for first left input
    let left = (witness[0][1], witness[1][1], witness[2][1]);
    range_check::witness::extend_multi(&mut witness, left.0, left.1, left.2);

    // Create multi-range-check witness for chained right inputs and results
    for i in 1..num + 1 {
        let right = (witness[3][i], witness[4][i], witness[5][i]);
        let output = (witness[0][i + 1], witness[1][i + 1], witness[2][i + 1]);
        range_check::witness::extend_multi(&mut witness, right.0, right.1, right.2);
        range_check::witness::extend_multi(&mut witness, output.0, output.1, output.2);
    }

    // Create multi-range-check witness for final bound
    let bound = (
        witness[0][num + 2],
        witness[1][num + 2],
        witness[2][num + 2],
    );
    range_check::witness::extend_multi(&mut witness, bound.0, bound.1, bound.2);

    witness
}

fn create_test_constraint_system_ffadd(
    opcodes: &[FFOps],
    foreign_field_modulus: BigUint,
    full: bool,
) -> ProverIndex<Vesta> {
    let (mut next_row, mut gates) = if full {
        full_circuit(opcodes, &foreign_field_modulus)
    } else {
        short_circuit(opcodes, &foreign_field_modulus)
    };

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    let cs = ConstraintSystem::create(gates).build().unwrap();
    let mut srs = SRS::<Vesta>::create(cs.domain.d1.size());
    srs.add_lagrange_basis(cs.domain.d1);
    let srs = Arc::new(srs);

    let (endo_q, _endo_r) = endos::<Pallas>();
    ProverIndex::<Vesta>::create(cs, endo_q, srs)
}

// helper to reduce lines of code in repetitive test structure
fn test_ffadd(
    foreign_field_modulus: BigUint,
    inputs: Vec<BigUint>,
    opcodes: &[FFOps],
    full: bool,
) -> ([Vec<PallasField>; COLUMNS], ProverIndex<Vesta>) {
    let index = create_test_constraint_system_ffadd(opcodes, foreign_field_modulus.clone(), full);

    let witness = if full {
        long_witness(&inputs, opcodes, foreign_field_modulus)
    } else {
        short_witness(&inputs, opcodes, foreign_field_modulus)
    };

    let all_rows = witness[0].len();

    for row in 0..all_rows {
        assert_eq!(
            index.cs.gates[row].verify_witness::<Vesta>(
                row,
                &witness,
                &index.cs,
                &witness[0][0..index.cs.public]
            ),
            Ok(())
        );
    }

    (witness, index)
}

// checks that the result cells of the witness are computed as expected
fn check_result(witness: [Vec<PallasField>; COLUMNS], result: Vec<ForeignElement<PallasField, 3>>) {
    for (i, res) in result.iter().enumerate() {
        assert_eq!(witness[0][i + 2], res[LO]);
        assert_eq!(witness[1][i + 2], res[MI]);
        assert_eq!(witness[2][i + 2], res[HI]);
    }
}

// checks the result of the overflow bit for one addition
fn check_ovf(witness: [Vec<PallasField>; COLUMNS], ovf: PallasField) {
    assert_eq!(witness[6][1], ovf);
}

// checks the result of the carry bits for one addition
fn check_carry(witness: [Vec<PallasField>; COLUMNS], carry: PallasField) {
    assert_eq!(witness[7][1], carry);
}

// computes the result of an addition
fn compute_sum(modulus: BigUint, left: &[u8], right: &[u8]) -> BigUint {
    let left_big = BigUint::from_bytes_be(left);
    let right_big = BigUint::from_bytes_be(right);
    (left_big + right_big) % modulus
}

// computes the result of a subtraction
fn compute_dif(modulus: BigUint, left: &[u8], right: &[u8]) -> BigUint {
    let left_big = BigUint::from_bytes_be(left);
    let right_big = BigUint::from_bytes_be(right);
    if left_big < right_big {
        left_big + modulus - right_big
    } else {
        left_big - right_big
    }
}

// obtains a random input of 32 bytes that fits in the foreign modulus
fn random_input(rng: &mut StdRng, modulus: BigUint, large: bool) -> Vec<u8> {
    let mut random_str = vec![];
    let mut random_big = BigUint::from_u128(2u128.pow(88)).unwrap().pow(3);
    while random_big > modulus {
        random_big = if large {
            rng.gen_biguint_below(&BigUint::from(2u32).pow(32))
        } else {
            rng.gen_biguint_below(&BigUint::from(2u32).pow(20))
        };
        random_str = random_big.to_bytes_be();
    }
    random_str
}

// obtains a random operation
fn random_operation(rng: &mut StdRng) -> FFOps {
    let op: u32 = rng.gen_range(0..2);
    match op {
        0 => FFOps::Add,
        1 => FFOps::Sub,
        _ => panic!("Invalid operation"),
    }
}

#[test]
// Add zero to zero. This checks that small amounts also get packed into limbs
fn test_zero_add() {
    test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::zero(), BigUint::zero()],
        &[FFOps::Add],
        false,
    );
}

#[test]
// Adding terms that are zero modulo the foreign field
fn test_zero_sum_foreign() {
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![secp256k1_modulus_bottom(), secp256k1_modulus_top()],
        &[FFOps::Add],
        false,
    );
    check_result(witness, vec![ForeignElement::zero()]);
}

#[test]
// Adding terms that are zero modulo the native field
fn test_zero_sum_native() {
    let native_modulus = PallasField::modulus_biguint();
    let one = BigUint::new(vec![1u32]);
    let mod_minus_one = native_modulus.clone() - one;
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![One::one(), mod_minus_one],
        &[FFOps::Add],
        false,
    );

    // Check result is the native modulus
    let native_limbs = ForeignElement::<PallasField, 3>::from_biguint(native_modulus);
    check_result(witness, vec![native_limbs]);
}

#[test]
fn test_one_plus_one() {
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![One::one(), One::one()],
        &[FFOps::Add],
        false,
    );
    // check result is 2
    let two = ForeignElement::from_be(&[2]);
    check_result(witness, vec![two]);
}

#[test]
// Adds two terms that are the maximum value in the foreign field
fn test_max_number() {
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![secp256k1_max(), secp256k1_max()],
        &[FFOps::Add],
        false,
    );

    // compute result in the foreign field after taking care of the exceeding bits
    let sum = secp256k1_max() + secp256k1_max();
    let sum_mod = sum - secp256k1_modulus();
    let sum_mod_limbs = ForeignElement::<PallasField, 3>::from_biguint(sum_mod);
    check_ovf(witness.clone(), PallasField::one());
    check_result(witness, vec![sum_mod_limbs]);
}

#[test]
// test 0 - 1 where (-1) is in the foreign field
// this is tested first as 0 + neg(1)
// and then as 0 - 1
// and it is checked that in both cases the result is the same
fn test_zero_minus_one() {
    // FIRST AS NEG
    let right_be_neg = ForeignElement::<PallasField, 3>::from_biguint(One::one())
        .neg(&secp256k1_modulus())
        .to_biguint();
    let right_for_neg: ForeignElement<PallasField, 3> =
        ForeignElement::from_biguint(right_be_neg.clone());
    let (witness_neg, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::zero(), right_be_neg],
        &[FFOps::Add],
        false,
    );
    check_result(witness_neg, vec![right_for_neg.clone()]);

    // NEXT AS SUB
    let (witness_sub, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::zero(), One::one()],
        &[FFOps::Sub],
        false,
    );
    check_result(witness_sub, vec![right_for_neg]);
}

#[test]
// test 1 - 1 + 1 where (-1) is in the foreign field
// the first check is done with sub(1, 1) and then with add(neg(neg(1)))
fn test_one_minus_one_plus_one() {
    let neg_neg_one = ForeignElement::<PallasField, 3>::from_biguint(One::one())
        .neg(&secp256k1_modulus())
        .neg(&secp256k1_modulus())
        .to_biguint();
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![One::one(), One::one(), neg_neg_one],
        &[FFOps::Sub, FFOps::Add],
        false,
    );
    // intermediate 1 - 1 should be zero
    // final 0 + 1 should be 1
    check_result(
        witness,
        vec![
            ForeignElement::zero(),
            ForeignElement::from_biguint(One::one()),
        ],
    );
}

#[test]
// test -1-1 where (-1) is in the foreign field
// first tested as neg(1) + neg(1)
// then tested as 0 - 1 - 1 )
// TODO: tested as 0 - ( 1 + 1) -> put sign in front of left instead (perhaps in the future we want this)
fn test_minus_minus() {
    let neg_one_for =
        ForeignElement::<PallasField, 3>::from_biguint(One::one()).neg(&secp256k1_modulus());
    let neg_one = neg_one_for.to_biguint();
    let neg_two = ForeignElement::<PallasField, 3>::from_biguint(BigUint::from_u32(2).unwrap())
        .neg(&secp256k1_modulus());
    let (witness_neg, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![neg_one.clone(), neg_one],
        &[FFOps::Add],
        false,
    );
    check_result(witness_neg, vec![neg_two.clone()]);

    let (witness_sub, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::zero(), One::one(), One::one()],
        &[FFOps::Sub, FFOps::Sub],
        false,
    );
    check_result(witness_sub, vec![neg_one_for, neg_two]);
}

#[test]
// test when the low carry is minus one
fn test_neg_carry_lo() {
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![
            BigUint::from_bytes_be(OVF_NEG_LO),
            BigUint::from_bytes_be(OVF_NEG_LO),
        ],
        &[FFOps::Add],
        false,
    );
    check_carry(witness, PallasField::zero());
}

#[test]
// test when the middle carry is minus one
fn test_neg_carry_mi() {
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![
            BigUint::from_bytes_be(OVF_NEG_MI),
            BigUint::from_bytes_be(OVF_NEG_MI),
        ],
        &[FFOps::Add],
        false,
    );
    check_carry(witness, -PallasField::one());
}

#[test]
// test when there is negative low carry and 0 middle limb (carry bit propagates)
fn test_propagate_carry() {
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![
            BigUint::from_bytes_be(OVF_ZERO_MI_NEG_LO),
            BigUint::from_bytes_be(OVF_ZERO_MI_NEG_LO),
        ],
        &[FFOps::Add],
        false,
    );
    check_carry(witness, -PallasField::one());
}

#[test]
// test when the both carries are minus one
fn test_neg_carries() {
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![
            BigUint::from_bytes_be(OVF_NEG_BOTH),
            BigUint::from_bytes_be(OVF_ZERO_MI_NEG_LO),
        ],
        &[FFOps::Add],
        false,
    );
    check_carry(witness, -PallasField::one());
}

#[test]
// test the upperbound of the result
fn test_upperbound() {
    test_ffadd(
        secp256k1_modulus(),
        vec![
            BigUint::from_bytes_be(OVF_LESS_HI_LEFT),
            BigUint::from_bytes_be(OVF_LESS_HI_RIGHT),
        ],
        &[FFOps::Add],
        false,
    );
}

#[test]
// test a carry that nullifies in the low limb
fn test_null_lo_carry() {
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![secp256k1_max(), BigUint::from_bytes_be(NULL_CARRY_LO)],
        &[FFOps::Add],
        false,
    );
    check_carry(witness, PallasField::zero());
}

#[test]
// test a carry that nullifies in the mid limb
fn test_null_mi_carry() {
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![secp256k1_max(), BigUint::from_bytes_be(NULL_CARRY_MI)],
        &[FFOps::Add],
        false,
    );
    check_carry(witness, PallasField::zero());
}

#[test]
// test a carry that nullifies in the mid limb
fn test_null_both_carry() {
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![secp256k1_max(), BigUint::from_bytes_be(NULL_CARRY_BOTH)],
        &[FFOps::Add],
        false,
    );
    check_carry(witness, PallasField::zero());
}

#[test]
// test sums without carry bits in any limb
fn test_no_carry_limbs() {
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::from_bytes_be(TIC), BigUint::from_bytes_be(TOC)],
        &[FFOps::Add],
        false,
    );
    check_carry(witness.clone(), PallasField::zero());
    // check middle limb is all ones
    let all_one_limb = PallasField::from(2u128.pow(88) - 1);
    assert_eq!(witness[1][2], all_one_limb);
}

#[test]
// test sum with carry only in low part
fn test_pos_carry_limb_lo() {
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::from_bytes_be(TIC), BigUint::from_bytes_be(TOC_LO)],
        &[FFOps::Add],
        false,
    );
    check_carry(witness, PallasField::zero());
}

#[test]
fn test_pos_carry_limb_mid() {
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::from_bytes_be(TIC), BigUint::from_bytes_be(TOC_MI)],
        &[FFOps::Add],
        false,
    );
    check_carry(witness, PallasField::one());
}

#[test]
fn test_pos_carry_limb_lo_mid() {
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::from_bytes_be(TIC), BigUint::from_bytes_be(TOC_TWO)],
        &[FFOps::Add],
        false,
    );
    check_carry(witness, PallasField::one());
}

#[test]
// Check it fails if given a wrong result (sum)
fn test_wrong_sum() {
    let (mut witness, index) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::from_bytes_be(TIC), BigUint::from_bytes_be(TOC)],
        &[FFOps::Add],
        true,
    );
    // wrong result
    let all_ones_limb = PallasField::from(2u128.pow(88) - 1);
    witness[0][2] = all_ones_limb;
    witness[0][12] = all_ones_limb;

    assert_eq!(
        index.cs.gates[1].verify_witness::<Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::ForeignFieldAdd, 3)),
    );
}

#[test]
// Check it fails if given a wrong result (difference)
fn test_wrong_dif() {
    let (mut witness, index) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::from_bytes_be(TIC), BigUint::from_bytes_be(TOC)],
        &[FFOps::Sub],
        true,
    );
    // wrong result
    witness[0][2] = PallasField::zero();
    witness[0][12] = PallasField::zero();

    assert_eq!(
        index.cs.gates[1].verify_witness::<Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::ForeignFieldAdd, 3)),
    );
}

#[test]
// Test subtraction of the foreign field
fn test_zero_sub_fmod() {
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::zero(), secp256k1_modulus()],
        &[FFOps::Sub],
        false,
    );
    // -f should be 0 mod f
    check_result(witness, vec![ForeignElement::zero()]);
}

#[test]
// Test subtraction of the foreign field maximum value
fn test_zero_sub_fmax() {
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![BigUint::zero(), secp256k1_max()],
        &[FFOps::Sub],
        false,
    );
    let negated =
        ForeignElement::<PallasField, 3>::from_biguint(secp256k1_max()).neg(&secp256k1_modulus());
    check_result(witness, vec![negated]);
}

// The order of the Pallas curve is 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001.
// The order of the Vesta curve is  0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001.

#[test]
// Test with Pasta curves where foreign field is smaller than the native field
fn test_pasta_add_max_vesta() {
    let vesta_modulus = VestaField::modulus_biguint();
    let right_input = field_max(vesta_modulus.clone());
    let (witness, _index) = test_ffadd(
        vesta_modulus.clone(),
        vec![BigUint::zero(), right_input.clone()],
        &[FFOps::Add],
        false,
    );
    let right = right_input % vesta_modulus;
    let right_foreign = ForeignElement::<PallasField, 3>::from_biguint(right);
    check_result(witness, vec![right_foreign]);
}

#[test]
// Test with Pasta curves where foreign field is smaller than the native field
fn test_pasta_sub_max_vesta() {
    let vesta_modulus = VestaField::modulus_biguint();
    let right_input = field_max(vesta_modulus.clone());
    let (witness, _index) = test_ffadd(
        vesta_modulus.clone(),
        vec![BigUint::zero(), right_input.clone()],
        &[FFOps::Sub],
        false,
    );
    let neg_max_vesta =
        ForeignElement::<PallasField, 3>::from_biguint(right_input).neg(&vesta_modulus);
    check_result(witness, vec![neg_max_vesta]);
}

#[test]
// Test with Pasta curves where foreign field is smaller than the native field
fn test_pasta_add_max_pallas() {
    let vesta_modulus = VestaField::modulus_biguint();
    let right_input = field_max(PallasField::modulus_biguint());
    let (witness, _index) = test_ffadd(
        vesta_modulus.clone(),
        vec![BigUint::zero(), right_input.clone()],
        &[FFOps::Add],
        false,
    );
    let right = right_input % vesta_modulus;
    let foreign_right = ForeignElement::<PallasField, 3>::from_biguint(right);
    check_result(witness, vec![foreign_right]);
}

#[test]
// Test with Pasta curves where foreign field is smaller than the native field
fn test_pasta_sub_max_pallas() {
    let vesta_modulus = VestaField::modulus_biguint();
    let right_input = field_max(PallasField::modulus_biguint());
    let (witness, _index) = test_ffadd(
        vesta_modulus.clone(),
        vec![BigUint::zero(), right_input.clone()],
        &[FFOps::Sub],
        false,
    );
    let neg_max_pallas =
        ForeignElement::<PallasField, 3>::from_biguint(right_input).neg(&vesta_modulus);
    check_result(witness, vec![neg_max_pallas]);
}

#[test]
// Test with a random addition
fn test_random_add() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let foreign_mod = secp256k1_modulus();
    let left_input = random_input(rng, foreign_mod.clone(), true);
    let right_input = random_input(rng, foreign_mod.clone(), true);
    let left_big = BigUint::from_bytes_be(&left_input);
    let right_big = BigUint::from_bytes_be(&right_input);
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![left_big.clone(), right_big.clone()],
        &[FFOps::Add],
        false,
    );
    let result =
        ForeignElement::<PallasField, 3>::from_biguint((left_big + right_big) % foreign_mod);
    check_result(witness, vec![result]);
}

#[test]
// Test with a random subtraction
fn test_random_sub() {
    let foreign_mod = secp256k1_modulus();
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let left_input = random_input(rng, foreign_mod.clone(), true);
    let right_input = random_input(rng, foreign_mod.clone(), true);
    let left_big = BigUint::from_bytes_be(&left_input);
    let right_big = BigUint::from_bytes_be(&right_input);
    let (witness, _index) = test_ffadd(
        secp256k1_modulus(),
        vec![left_big.clone(), right_big.clone()],
        &[FFOps::Sub],
        false,
    );
    let result = if left_big < right_big {
        ForeignElement::<PallasField, 3>::from_biguint(left_big + foreign_mod - right_big)
    } else {
        ForeignElement::<PallasField, 3>::from_biguint(left_big - right_big)
    };
    check_result(witness, vec![result]);
}

#[test]
// Random test with foreign field being the native field add
fn test_foreign_is_native_add() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let pallas = PallasField::modulus_biguint();
    let left_input = random_input(rng, pallas.clone(), true);
    let right_input = random_input(rng, pallas.clone(), true);
    let (witness, _index) = test_ffadd(
        pallas.clone(),
        vec![
            BigUint::from_bytes_be(&left_input),
            BigUint::from_bytes_be(&right_input),
        ],
        &[FFOps::Add],
        false,
    );
    // check result was computed correctly
    let sum_big = compute_sum(pallas, &left_input, &right_input);
    let result = ForeignElement::<PallasField, 3>::from_biguint(sum_big.clone());
    check_result(witness, vec![result.clone()]);
    // check result is in the native field
    let two_to_limb = PallasField::from(TWO_TO_LIMB);
    let left = ForeignElement::<PallasField, 3>::from_be(&left_input);
    let right = ForeignElement::<PallasField, 3>::from_be(&right_input);
    let left = (left[HI] * two_to_limb + left[MI]) * two_to_limb + left[LO];
    let right = (right[HI] * two_to_limb + right[MI]) * two_to_limb + right[LO];
    let sum = left + right;
    let result = (result[HI] * two_to_limb + result[MI]) * two_to_limb + result[LO];
    let sum_from = PallasField::from(sum_big);
    assert_eq!(result, sum);
    assert_eq!(result, sum_from);
}

#[test]
// Random test with foreign field being the native field add
fn test_foreign_is_native_sub() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let pallas = PallasField::modulus_biguint();
    let left_input = random_input(rng, pallas.clone(), true);
    let right_input = random_input(rng, pallas.clone(), true);
    let (witness, _index) = test_ffadd(
        pallas.clone(),
        vec![
            BigUint::from_bytes_be(&left_input),
            BigUint::from_bytes_be(&right_input),
        ],
        &[FFOps::Sub],
        false,
    );
    // check result was computed correctly
    let dif_big = compute_dif(pallas, &left_input, &right_input);
    let result = ForeignElement::<PallasField, 3>::from_biguint(dif_big.clone());
    check_result(witness, vec![result.clone()]);
    // check result is in the native field
    let two_to_limb = PallasField::from(TWO_TO_LIMB);
    let left = ForeignElement::<PallasField, 3>::from_be(&left_input);
    let right = ForeignElement::<PallasField, 3>::from_be(&right_input);
    let left = (left[HI] * two_to_limb + left[MI]) * two_to_limb + left[LO];
    let right = (right[HI] * two_to_limb + right[MI]) * two_to_limb + right[LO];
    let dif = left - right;
    let result = (result[HI] * two_to_limb + result[MI]) * two_to_limb + result[LO];
    let dif_from = PallasField::from(dif_big);
    assert_eq!(result, dif);
    assert_eq!(result, dif_from);
}

#[test]
// Test with a random addition
fn test_random_small_add() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    // 2^200 - 75 is prime with 200 bits (3 limbs but smaller than Pallas)
    let prime = BigUint::from_u128(2u128.pow(100)).unwrap().pow(2) - BigUint::from_u32(75).unwrap();
    let foreign_mod = prime.clone();
    let left_input = random_input(rng, foreign_mod.clone(), false);
    let right_input = random_input(rng, foreign_mod.clone(), false);
    let (witness, _index) = test_ffadd(
        prime,
        vec![
            BigUint::from_bytes_be(&left_input),
            BigUint::from_bytes_be(&right_input),
        ],
        &[FFOps::Add],
        false,
    );
    let result = compute_sum(foreign_mod, &left_input, &right_input);
    check_result(
        witness,
        vec![ForeignElement::<PallasField, 3>::from_biguint(result)],
    );
}

#[test]
// Test with a random subtraction
fn test_random_small_sub() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    // 2^200 - 75 is prime with 200 bits (3 limbs but smaller than Pallas)
    let prime = BigUint::from_u128(2u128.pow(100)).unwrap().pow(2) - BigUint::from_u32(75).unwrap();
    let foreign_mod = prime.clone();
    let left_input = random_input(rng, foreign_mod.clone(), false);
    let right_input = random_input(rng, foreign_mod.clone(), false);
    let (witness, _index) = test_ffadd(
        prime,
        vec![
            BigUint::from_bytes_be(&left_input),
            BigUint::from_bytes_be(&right_input),
        ],
        &[FFOps::Sub],
        false,
    );
    let result = compute_dif(foreign_mod, &left_input, &right_input);
    check_result(
        witness,
        vec![ForeignElement::<PallasField, 3>::from_biguint(result)],
    );
}

#[test]
// Test with bad parameters in bound check
fn test_bad_bound() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let foreign_mod = secp256k1_modulus();
    let left_input = BigUint::from_bytes_be(&random_input(rng, foreign_mod.clone(), false));
    let right_input = BigUint::from_bytes_be(&random_input(rng, foreign_mod.clone(), false));
    let (mut witness, mut index) = test_ffadd(
        foreign_mod,
        vec![left_input, right_input],
        &[FFOps::Add],
        true,
    );
    // Modify sign of bound
    // It should be constrained that sign needs to be 1
    index.cs.gates[2].coeffs[3] = -PallasField::two();
    assert_eq!(
        index.cs.gates[2].check_ffadd_sign(FFOps::Add),
        Err("Gate is not performing addition".to_string()),
    );
    index.cs.gates[2].coeffs[3] = PallasField::one();
    // Modify overflow to check first the copy constraint and then the ovf constraint
    witness[6][2] = -PallasField::one();
    assert_eq!(
        index.cs.gates[2].verify_witness::<Vesta>(
            2,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::CopyConstraint {
            typ: GateType::ForeignFieldAdd,
            src: Wire { row: 2, col: 6 },
            dst: Wire { row: 0, col: 0 }
        }),
    );
    witness[0][0] = -PallasField::one();
    assert_eq!(
        index.cs.gates[2].verify_witness::<Vesta>(
            2,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::ForeignFieldAdd, 1)),
    );
    witness[6][2] = PallasField::one();
    witness[0][0] = PallasField::one();
    assert_eq!(
        index.cs.gates[2].verify_witness::<Vesta>(
            2,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(()),
    );
}

#[test]
// Test with bad left input
fn test_random_bad_input() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let foreign_mod = secp256k1_modulus();
    let left_input = random_input(rng, foreign_mod.clone(), false);
    let right_input = random_input(rng, foreign_mod, false);
    let (mut witness, index) = test_ffadd(
        secp256k1_modulus(),
        vec![
            BigUint::from_bytes_be(&left_input),
            BigUint::from_bytes_be(&right_input),
        ],
        &[FFOps::Sub],
        true,
    );
    // First modify left input only to cause an invalid copy constraint
    witness[0][1] += PallasField::one();
    assert_eq!(
        index.cs.gates[1].verify_witness::<Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::CopyConstraint {
            typ: GateType::ForeignFieldAdd,
            src: Wire { row: 1, col: 0 },
            dst: Wire { row: 4, col: 0 }
        }),
    );
    // then modify the value in the range check to cause an invalid FFAdd constraint
    witness[0][4] += PallasField::one();
    assert_eq!(
        index.cs.gates[1].verify_witness::<Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::ForeignFieldAdd, 3)),
    );
}

#[test]
// Test with bad parameters
fn test_random_bad_parameters() {
    let rng = &mut StdRng::from_seed(RNG_SEED);
    let foreign_mod = secp256k1_modulus();
    let left_input = random_input(rng, foreign_mod.clone(), false);
    let right_input = random_input(rng, foreign_mod, false);
    let (mut witness, mut index) = test_ffadd(
        secp256k1_modulus(),
        vec![
            BigUint::from_bytes_be(&left_input),
            BigUint::from_bytes_be(&right_input),
        ],
        &[FFOps::Add],
        false,
    );
    // Modify bot carry
    witness[7][1] += PallasField::one();
    assert_eq!(
        index.cs.gates[1].verify_witness::<Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::ForeignFieldAdd, 3)),
    );
    witness[7][1] -= PallasField::one();
    // Modify overflow
    witness[6][1] += PallasField::one();
    assert_eq!(
        index.cs.gates[1].verify_witness::<Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::ForeignFieldAdd, 3)),
    );
    witness[6][1] -= PallasField::one();
    // Modify sign
    index.cs.gates[1].coeffs[3] = PallasField::zero() - index.cs.gates[1].coeffs[3];
    assert_eq!(
        index.cs.gates[1].verify_witness::<Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Err(CircuitGateError::Constraint(GateType::ForeignFieldAdd, 3)),
    );
    index.cs.gates[1].coeffs[3] = PallasField::zero() - index.cs.gates[1].coeffs[3];
    // Check back to normal
    assert_eq!(
        index.cs.gates[1].verify_witness::<Vesta>(
            1,
            &witness,
            &index.cs,
            &witness[0][0..index.cs.public]
        ),
        Ok(()),
    );
}

#[test]
// Test with chain of random operations
fn test_random_chain() {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    let nops = 20;
    let foreign_mod = secp256k1_modulus();
    let inputs = (0..nops + 1)
        .into_iter()
        .map(|_| random_input(rng, foreign_mod.clone(), true))
        .collect::<Vec<_>>();
    let big_inputs = inputs
        .clone()
        .into_iter()
        .map(|v| BigUint::from_bytes_be(&v))
        .collect::<Vec<_>>();
    let operations = (0..nops)
        .into_iter()
        .map(|_| random_operation(rng))
        .collect::<Vec<_>>();
    let (witness, _index) = test_ffadd(secp256k1_modulus(), big_inputs, &operations, true);
    let mut left = vec![inputs[0].clone()];
    let results: Vec<ForeignElement<PallasField, 3>> = operations
        .iter()
        .enumerate()
        .map(|(i, op)| {
            let result = match op {
                FFOps::Add => compute_sum(foreign_mod.clone(), &left[i], &inputs[i + 1]),
                FFOps::Sub => compute_dif(foreign_mod.clone(), &left[i], &inputs[i + 1]),
            };
            left.push(result.to_bytes_be());
            ForeignElement::<PallasField, 3>::from_biguint(result)
        })
        .collect();
    check_result(witness, results);
}

// Prove and verify used for end-to-end tests
fn prove_and_verify(operation_count: usize) {
    let rng = &mut StdRng::from_seed(RNG_SEED);

    // Create random operations
    let operations = (0..operation_count)
        .into_iter()
        .map(|_| random_operation(rng))
        .collect::<Vec<_>>();

    // Create foreign modulus
    let foreign_field_modulus = secp256k1_modulus();

    // Create circuit
    // Initialize public input
    let (mut next_row, mut gates) = short_circuit(&operations, &foreign_field_modulus);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    // Create randm inputs
    let inputs = (0..operation_count + 1)
        .into_iter()
        .map(|_| BigUint::from_bytes_be(&random_input(rng, foreign_field_modulus.clone(), true)))
        .collect::<Vec<BigUint>>();

    // Create witness
    let witness = short_witness(&inputs, &operations, foreign_field_modulus);

    assert!(TestFramework::<Vesta>::default()
        .gates(gates)
        .witness(witness)
        .public_inputs(vec![PallasField::one()])
        .setup()
        .prove_and_verify::<BaseSponge, ScalarSponge>()
        .is_ok());
}

// Prove and verify a randomly generated operation (only ffadd)
#[test]
fn prove_and_verify_1() {
    prove_and_verify(1);
}

// Prove and verify a chain of 50 randomly generated operations (only ffadd)
#[test]
fn prove_and_verify_50() {
    prove_and_verify(50);
}

// Extends a gate with the final bound range check
fn extend_gate_bound_rc(gates: &mut Vec<CircuitGate<PallasField>>) -> usize {
    let bound_row = gates.len() - 1;
    let mut new_row = gates.len();
    CircuitGate::extend_multi_range_check(gates, &mut new_row);
    gates.connect_cell_pair((bound_row, 0), (bound_row + 1, 0));
    gates.connect_cell_pair((bound_row, 1), (bound_row + 2, 0));
    gates.connect_cell_pair((bound_row, 2), (bound_row + 3, 0));
    new_row
}

// Extends a witness with the final bound range check
fn extend_witness_bound_rc(witness: &mut [Vec<PallasField>; COLUMNS]) {
    let bound_row = witness[0].len() - 1;
    let bound_lo = witness[0][bound_row];
    let bound_mi = witness[1][bound_row];
    let bound_hi = witness[2][bound_row];
    extend_multi(witness, bound_lo, bound_mi, bound_hi)
}

// Test with FFAdd gates without range checks
#[test]
fn test_ffadd_no_rc() {
    let operation_count = 3;
    let rng = &mut StdRng::from_seed(RNG_SEED);

    // Create foreign modulus
    let foreign_mod = secp256k1_modulus();

    // Create random operations
    let operations = (0..operation_count)
        .into_iter()
        .map(|_| random_operation(rng))
        .collect::<Vec<_>>();

    // Create circuit
    let (mut next_row, mut gates) = short_circuit(&operations, &foreign_mod);

    extend_gate_bound_rc(&mut gates);

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    let cs = ConstraintSystem::create(gates).build().unwrap();

    // Create inputs
    let inputs = (0..operation_count + 1)
        .into_iter()
        .map(|_| BigUint::from_bytes_be(&random_input(rng, foreign_mod.clone(), false)))
        .collect::<Vec<BigUint>>();

    // Create witness
    let mut witness = short_witness(&inputs, &operations, foreign_mod);

    extend_witness_bound_rc(&mut witness);

    for row in 0..witness[0].len() {
        assert_eq!(
            cs.gates[row].verify_witness::<Vesta>(row, &witness, &cs, &witness[0][0..cs.public]),
            Ok(())
        );
    }
}

// TESTS CHANGING NATIVE FIELD

#[test]
// Tests targeting each custom constraint with Vesta (foreign field modulus) on Pallas (native field modulus)
fn test_vesta_on_pallas() {
    let test =
        run_test::<Pallas, PallasBaseSponge, PallasScalarSponge>(&VestaField::modulus_biguint());
    assert_eq!(test.0, Ok(()));
}

#[test]
// Tests targeting each custom constraint with Pallas (foreign field modulus) on Vesta (native field modulus)
fn test_pallas_on_vesta() {
    let test =
        run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(&PallasField::modulus_biguint());
    assert_eq!(test.0, Ok(()));
}

#[test]
// Tests targeting each custom constraint with Vesta (foreign field modulus) on Vesta (native field modulus)
fn test_vesta_on_vesta() {
    let test =
        run_test::<Vesta, VestaBaseSponge, VestaScalarSponge>(&VestaField::modulus_biguint());
    assert_eq!(test.0, Ok(()));
}

#[test]
// Tests targeting each custom constraint with Pallas (foreign field modulus) on Pallas (native field modulus)
fn test_pallas_on_pallas() {
    let test =
        run_test::<Pallas, PallasBaseSponge, PallasScalarSponge>(&PallasField::modulus_biguint());
    assert_eq!(test.0, Ok(()));
}

// Boilerplate for tests
fn run_test<G: KimchiCurve, EFqSponge, EFrSponge>(
    foreign_field_modulus: &BigUint,
) -> (CircuitGateResult<()>, [Vec<G::ScalarField>; COLUMNS])
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    let rng = &mut StdRng::from_seed(RNG_SEED);

    // Create foreign field addition gates
    let (mut next_row, mut gates) = short_circuit(&[FFOps::Add], foreign_field_modulus);

    let left_input =
        BigUint::from_bytes_be(&random_input(rng, foreign_field_modulus.clone(), true));
    let right_input =
        BigUint::from_bytes_be(&random_input(rng, foreign_field_modulus.clone(), true));

    // Compute addition witness
    let witness = short_witness(
        &vec![left_input, right_input],
        &[FFOps::Add],
        foreign_field_modulus.clone(),
    );

    // Temporary workaround for lookup-table/domain-size issue
    for _ in 0..(1 << 13) {
        gates.push(CircuitGate::zero(Wire::for_row(next_row)));
        next_row += 1;
    }

    let cs = ConstraintSystem::create(gates.clone()).build().unwrap();

    // Perform witness verification that everything is ok before invalidation (quick checks)
    for (row, gate) in gates.iter().enumerate().take(witness[0].len()) {
        let result = gate.verify_witness::<G>(row, &witness, &cs, &witness[0][0..cs.public]);
        if result.is_err() {
            return (result, witness);
        }
    }

    (Ok(()), witness)
}
