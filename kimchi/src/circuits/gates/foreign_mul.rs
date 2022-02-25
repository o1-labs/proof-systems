// Foreign field multiplication
//
// https://hackmd.io/XZUHHGpDQsSOs0dUGugB5w
//
// Globals:
//     * n: native field modulus
//     * p: foreign field modulus
//
// Inputs:
//     * a: first operand a \in Fp
//     * b: second operand b \in Fp
//
// Witness:
//     * q: \in Fp
//     * r: such that a*b = q*p +r
//
// Input structure:
//
//    Rows*  Contents
//    0..3   a
//    4..7   b
//
//    (*) Row offsets
//
// Contents structure:
//
//    Each foreign field element x is decomposed into three 88-bit limbs x0, x1, x2 s.t. x = x0x1x2 in
//    little-endian byte order (i.e. x = x2*2^{2b} + x1*2^b + x0)
//
//      x0 = x0p0x0p1x0p2x0p3x0p4x0p5x0c0x0c1x0c2x0c3x0c4x0c5x0c6x0c7
//      x1 = x1p0x1p1x1p2x1p3x1p4x1p5x1c0x1c1x1c2x1c3x1c4x1c5x1c6x1c7
//      x2 = x2p0x2p1x2p2x2p3x2c0x2c1x2c2x2c3x2c4x2c5x2c6x2c7x2c8x2c9x2c10x2c11x2c12x2c13x2c14x2c15x2c16x2c17x2c18x2c19
//
//    where
//      * xNpi is a 12-bit sublimb of limb xN
//      * xNci is a 2-bit "crumb" sublimb of xN
//
//          Rows -->
//          0              1              2              3
//   C  0 | x0           | x1             x2
//   o  1 | plookup x0p0 | plookup x1p0 | plookup x2p0 | plookup x0p4
//   l  2 | plookup x0p1 | plookup x1p1 | plookup x2p1 | plookup x0p5
//   s  3 | plookup x0p2 | plookup x1p2 | plookup x2p2 | plookup x1p4
//   |  4 | plookup x0p3 | plookup x1p3 | plookup x2p3 | plookup x1p5
//  \ / 5 | copy x0p4    | copy x1p4    | crumb x2c0   | crumb x2c10
//   '  6 | copy x0p5    | copy x1p5    | crumb x2c1   | crumb x2c11
//      7 | crumb x0c0   | crumb x1c0   | crumb x2c2   | crumb x2c12
//      8 | crumb x0c1   | crumb x1c1   | crumb x2c3   | crumb x2c13
//      9 | crumb x0c2   | crumb x1c2   | crumb x2c4   | crumb x2c14
//     10 | crumb x0c3   | crumb x1c3   | crumb x2c5   | crumb x2c15
//     11 | crumb x0c4   | crumb x1c4   | crumb x2c6   | crumb x2c16
//     12 | crumb x0c5   | crumb x1c5   | crumb x2c7   | crumb x2c17
//     13 | crumb x0c6   | crumb x1c6   | crumb x2c8   | crumb x2c18
//     14 | crumb x0c7   | crumb x1c7   | crumb x2c9   | crumb x2c19
//
//    The 12-bit chunks are constrained with plookups and the 2-bit crumbs constrained with
//    degree-4 constraints of the form x*(x - 1)*(x - 2)*(x - 3)

use array_init::array_init;
use num_bigint::BigUint;
use rand::prelude::StdRng;
use rand::SeedableRng;

use ark_ff::{FftField, PrimeField};

use crate::alphas::{self, ConstraintType};
use crate::circuits::constraints::ConstraintSystem;
use crate::circuits::expr::{self, Column, E};
use crate::circuits::gate::{CircuitGate, GateType};
use crate::circuits::polynomials;
use crate::circuits::scalars::ProofEvaluations;
use crate::circuits::wires::{GateWires, COLUMNS};
use o1_utils::FieldHelpers;

pub const CIRCUIT_GATE_COUNT: usize = 3;

const MAX_LIMBS: usize = 3;
const LIMB_SIZE: usize = 88;

fn gate_type_to_selector<F: FftField>(typ: GateType) -> [F; CIRCUIT_GATE_COUNT] {
    match typ {
        GateType::ForeignMul0 => [F::one(), F::zero(), F::zero()],
        GateType::ForeignMul1 => [F::zero(), F::one(), F::zero()],
        GateType::ForeignMul2 => [F::zero(), F::zero(), F::one()],
        _ => [F::zero(); CIRCUIT_GATE_COUNT],
    }
}

impl<F: FftField> CircuitGate<F> {
    /// Create foreign multiplication gate
    pub fn create_foreign_mul(wires: &[GateWires; 8]) -> Vec<Self> {
        vec![
            /* Input: a */
            CircuitGate {
                typ: GateType::ForeignMul0,
                wires: wires[0],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::ForeignMul0,
                wires: wires[1],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::ForeignMul1,
                wires: wires[2],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::ForeignMul2,
                wires: wires[3],
                coeffs: vec![],
            },
            /* Input: b */
            CircuitGate {
                typ: GateType::ForeignMul0,
                wires: wires[4],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::ForeignMul0,
                wires: wires[5],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::ForeignMul1,
                wires: wires[6],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::ForeignMul2,
                wires: wires[7],
                coeffs: vec![],
            },
        ]
    }

    pub fn verify_foreign_mul(
        &self,
        row: usize,
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
    ) -> Result<(), String> {
        // Witness row shorthands
        let curr: [F; COLUMNS] = array_init(|i| witness[i][row]);
        let next: [F; COLUMNS] = array_init(|i| witness[i][row + 1]);

        // Columns types that need to be evaluated for this gate to work
        let evaluated_cols = {
            let mut h = std::collections::HashSet::new();
            for i in 0..COLUMNS {
                h.insert(Column::Witness(i));
            }
            h.insert(Column::Index(GateType::ForeignMul0));
            h.insert(Column::Index(GateType::ForeignMul1));
            h.insert(Column::Index(GateType::ForeignMul2));
            h
        };

        // Setup temporary powers of alpha
        let mut powers_of_alpha = alphas::Builder::default();
        let alphas = powers_of_alpha.register(
            ConstraintType::Gate,
            polynomials::foreign_mul::CONSTRAINTS_1,
        );

        // Get constraints for this circuit gate
        let constraints = polynomials::foreign_mul::get_circuit_gate_constraints::<F>(self.typ);

        // Combine constraints using power of alpha
        let constraints = E::combine_constraints(alphas.take(constraints.len()), constraints);

        // Linearize
        let linearized = constraints.linearize(evaluated_cols).unwrap();

        // Setup proof evaluations
        let rng = &mut StdRng::from_seed([0u8; 32]);
        let mut eval = |witness| ProofEvaluations {
            w: witness,
            z: F::rand(rng),
            s: array_init(|_| F::rand(rng)),
            generic_selector: F::zero(),
            poseidon_selector: F::zero(),
            lookup: None,
            foreign_mul_selector: gate_type_to_selector(self.typ),
        };
        let evals = vec![eval(curr), eval(next)];

        // Setup circuit constants
        let constants = expr::Constants {
            alpha: F::rand(rng),
            beta: F::rand(rng),
            gamma: F::rand(rng),
            joint_combiner: F::rand(rng),
            endo_coefficient: cs.endo,
            mds: vec![],
            foreign_modulus: cs.foreign_modulus.clone(),
        };

        let pt = F::rand(rng);

        // Evaluate constraints
        match linearized
            .constant_term
            .evaluate_(cs.domain.d1, pt, &evals, &constants)
        {
            Ok(x) => {
                if x == F::zero() {
                    Ok(())
                } else {
                    Err(format!("Invalid {:?} constraint", self.typ))
                }
            }
            Err(_) => Err(format!("Failed to evaluate {:?} constraint", self.typ)),
        }
    }

    pub fn foreign_mul(&self, typ: GateType) -> F {
        if self.typ == typ {
            F::one()
        } else {
            F::zero()
        }
    }
}

//
// Witness computation (TODO: make dynamic)
//

enum WitnessCell {
    Copy(CopyWitnessCell),
    Limb,
    Sublimb(SublimbWitnessCell),
    Zero,
}

struct CopyWitnessCell {
    row: usize, // Cell row
    col: usize, // Cell col
}
impl CopyWitnessCell {
    const fn create(row: usize, col: usize) -> WitnessCell {
        WitnessCell::Copy(CopyWitnessCell { row, col })
    }
}

struct LimbWitnessCell;
impl LimbWitnessCell {
    const fn create() -> WitnessCell {
        WitnessCell::Limb
    }
}

struct SublimbWitnessCell {
    row: usize,   // Cell row
    col: usize,   // Cell col
    start: usize, // Starting bit offset
    end: usize,   // Ending bit offset (exclusive)
}
impl SublimbWitnessCell {
    // Params: source (row, col), starting bit offset and ending bit offset (exclusive)
    const fn create(row: usize, col: usize, start: usize, end: usize) -> WitnessCell {
        WitnessCell::Sublimb(SublimbWitnessCell {
            row,
            col,
            start,
            end,
        })
    }
}

struct ZeroWitnessCell;
impl ZeroWitnessCell {
    const fn create() -> WitnessCell {
        WitnessCell::Zero
    }
}

// Generate witness in shape that constraints expect (TODO: static for now, make dynamic)
const WITNESS_SHAPE: [[WitnessCell; COLUMNS]; 4] = [
    /* row 1, ForeignMul0 row */
    [
        LimbWitnessCell::create(),
        /* 12-bit plookups */
        SublimbWitnessCell::create(0, 0, 0, 12),
        SublimbWitnessCell::create(0, 0, 12, 24),
        SublimbWitnessCell::create(0, 0, 24, 36),
        SublimbWitnessCell::create(0, 0, 36, 48),
        /* 12-bit copies */
        SublimbWitnessCell::create(0, 0, 48, 60),
        SublimbWitnessCell::create(0, 0, 60, 72),
        /* 2-bit crumbs */
        SublimbWitnessCell::create(0, 0, 72, 74),
        SublimbWitnessCell::create(0, 0, 74, 76),
        SublimbWitnessCell::create(0, 0, 76, 78),
        SublimbWitnessCell::create(0, 0, 78, 80),
        SublimbWitnessCell::create(0, 0, 80, 82),
        SublimbWitnessCell::create(0, 0, 82, 84),
        SublimbWitnessCell::create(0, 0, 84, 86),
        SublimbWitnessCell::create(0, 0, 86, 88),
    ],
    /* row 2, ForeignMul0 row */
    [
        LimbWitnessCell::create(),
        /* 12-bit plookups */
        SublimbWitnessCell::create(1, 0, 0, 12),
        SublimbWitnessCell::create(1, 0, 12, 24),
        SublimbWitnessCell::create(1, 0, 24, 36),
        SublimbWitnessCell::create(1, 0, 36, 48),
        /* 12-bit copies */
        SublimbWitnessCell::create(1, 0, 48, 60),
        SublimbWitnessCell::create(1, 0, 60, 72),
        /* 2-bit crumbs */
        SublimbWitnessCell::create(1, 0, 72, 74),
        SublimbWitnessCell::create(1, 0, 74, 76),
        SublimbWitnessCell::create(1, 0, 76, 78),
        SublimbWitnessCell::create(1, 0, 78, 80),
        SublimbWitnessCell::create(1, 0, 80, 82),
        SublimbWitnessCell::create(1, 0, 82, 84),
        SublimbWitnessCell::create(1, 0, 84, 86),
        SublimbWitnessCell::create(1, 0, 86, 88),
    ],
    /* row 3, ForeignMul1 row */
    [
        LimbWitnessCell::create(),
        /* 12-bit plookups */
        SublimbWitnessCell::create(2, 0, 0, 12),
        SublimbWitnessCell::create(2, 0, 12, 24),
        SublimbWitnessCell::create(2, 0, 24, 36),
        SublimbWitnessCell::create(2, 0, 36, 48),
        /* 2-bit crumbs */
        SublimbWitnessCell::create(2, 0, 48, 50),
        SublimbWitnessCell::create(2, 0, 50, 52),
        SublimbWitnessCell::create(2, 0, 52, 54),
        SublimbWitnessCell::create(2, 0, 54, 56),
        SublimbWitnessCell::create(2, 0, 56, 58),
        SublimbWitnessCell::create(2, 0, 58, 60),
        SublimbWitnessCell::create(2, 0, 60, 62),
        SublimbWitnessCell::create(2, 0, 62, 64),
        SublimbWitnessCell::create(2, 0, 64, 66),
        SublimbWitnessCell::create(2, 0, 66, 68),
    ],
    /* row 4, ForeignMul2 row */
    [
        ZeroWitnessCell::create(),
        /* 12-bit plookups */
        CopyWitnessCell::create(0, 5),
        CopyWitnessCell::create(0, 6),
        CopyWitnessCell::create(1, 5),
        CopyWitnessCell::create(1, 6),
        /* 2-bit crumbs */
        SublimbWitnessCell::create(2, 0, 68, 70),
        SublimbWitnessCell::create(2, 0, 70, 72),
        SublimbWitnessCell::create(2, 0, 72, 74),
        SublimbWitnessCell::create(2, 0, 74, 76),
        SublimbWitnessCell::create(2, 0, 76, 78),
        SublimbWitnessCell::create(2, 0, 78, 80),
        SublimbWitnessCell::create(2, 0, 80, 82),
        SublimbWitnessCell::create(2, 0, 82, 84),
        SublimbWitnessCell::create(2, 0, 84, 86),
        SublimbWitnessCell::create(2, 0, 86, 88),
    ],
];

fn limb_to_sublimb<F: PrimeField>(fe: F, start: usize, end: usize) -> F {
    F::from_bits(&fe.to_bits()[start..end]).expect("failed to deserialize field bits")
}

fn init_foreign_mul_row<F: PrimeField>(witness: &mut [Vec<F>; COLUMNS], row: usize, limb: F) {
    for col in 0..COLUMNS {
        match &WITNESS_SHAPE[row][col] {
            WitnessCell::Copy(copy_cell) => {
                witness[col][row] = witness[copy_cell.col][copy_cell.row];
            }
            WitnessCell::Limb => {
                witness[col][row] = limb;
            }
            WitnessCell::Sublimb(sublimb_cell) => {
                witness[col][row] = limb_to_sublimb(
                    witness[sublimb_cell.col][sublimb_cell.row], // limb cell (row, col)
                    sublimb_cell.start,                          // starting bit
                    sublimb_cell.end,                            // ending bit (exclusive)
                );
            }
            WitnessCell::Zero => {
                witness[col][row] = F::zero();
            }
        }
    }
}

pub fn create_witness<F: PrimeField>(a: BigUint) -> [Vec<F>; COLUMNS] {
    assert!(a.bits() <= (MAX_LIMBS * LIMB_SIZE) as u64);
    let mut witness: [Vec<F>; COLUMNS] = array_init(|_| vec![F::zero(); 4]);
    let mut last_row_number = 0;

    for (row, chunk) in a
        .to_bytes_le() // F::from_bytes() below is little-endian
        .chunks(LIMB_SIZE / 8 + (LIMB_SIZE % 8 != 0) as usize)
        .enumerate()
    {
        // Convert chunk to field element and store in column 0
        let mut limb_bytes = chunk.to_vec();
        limb_bytes.resize(32 /* F::size_in_bytes() */, 0);
        let limb_fe = F::from_bytes(&limb_bytes).expect("failed to deserialize limb field bytes");

        // Initialize the row based on the limb and public input shape
        init_foreign_mul_row(&mut witness, row, limb_fe);
        last_row_number += 1;
    }

    // Initialize last row
    init_foreign_mul_row(&mut witness, last_row_number, F::zero());
    witness
}

#[cfg(test)]
mod tests {
    use crate::circuits::{
        constraints::ConstraintSystem, gate::CircuitGate, gates::foreign_mul::create_witness,
        polynomial::COLUMNS, wires::Wire,
    };

    use ark_ec::AffineCurve;
    use ark_ff::One;
    use mina_curves::pasta::{pallas, vesta};
    use num_bigint::BigUint;

    use array_init::array_init;

    type PallasField = <pallas::Affine as AffineCurve>::BaseField;
    type VestaField = <vesta::Affine as AffineCurve>::BaseField;

    fn create_test_constraint_system() -> ConstraintSystem<PallasField> {
        let wires = array_init(|i| Wire::new(i));
        let gates = CircuitGate::<PallasField>::create_foreign_mul(&wires);

        ConstraintSystem::create(
            gates,
            vec![],
            oracle::pasta::fp::params(),
            o1_utils::packed_modulus::<PallasField>(o1_utils::get_modulus::<VestaField>()),
            0,
        )
        .unwrap()
    }

    fn biguint_from_hex_le(hex: &str) -> BigUint {
        let mut bytes = hex::decode(hex).expect("invalid hex");
        bytes.reverse();
        BigUint::from_bytes_le(&bytes)
    }

    #[test]
    fn verify_foreign_mul0_zero_witness() {
        let cs = create_test_constraint_system();
        let witness: [Vec<PallasField>; COLUMNS] = array_init(|_| vec![PallasField::from(0); 2]);

        // gates[0] is ForeignMul0
        assert_eq!(cs.gates[0].verify_foreign_mul(0, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_foreign_mul0_one_witness() {
        let cs = create_test_constraint_system();
        let witness: [Vec<PallasField>; COLUMNS] = array_init(|_| vec![PallasField::from(1); 2]);

        // gates[0] is ForeignMul0
        assert_eq!(
            cs.gates[0].verify_foreign_mul(0, &witness, &cs),
            Err("Invalid ForeignMul0 constraint".to_string())
        );
    }

    #[test]
    fn verify_foreign_mul0_valid_witness() {
        let cs = create_test_constraint_system();

        let witness: [Vec<PallasField>; 15] = create_witness(biguint_from_hex_le(
            "1112223334445556667777888999aaabbbcccdddeeefff111222333444555611",
        ));

        // gates[0] is ForeignMul0
        assert_eq!(cs.gates[0].verify_foreign_mul(0, &witness, &cs), Ok(()));

        // gates[1] is ForeignMul0
        assert_eq!(cs.gates[1].verify_foreign_mul(1, &witness, &cs), Ok(()));

        let witness: [Vec<PallasField>; 15] = create_witness(biguint_from_hex_le(
            "f59abe33f5d808f8df3e63984621b01e375585fea8dd4030f71a0d80ac06d423",
        ));

        // gates[0] is ForeignMul0
        assert_eq!(cs.gates[0].verify_foreign_mul(0, &witness, &cs), Ok(()));

        // gates[1] is ForeignMul0
        assert_eq!(cs.gates[1].verify_foreign_mul(1, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_foreign_mul0_invalid_witness() {
        let cs = create_test_constraint_system();

        let mut witness: [Vec<PallasField>; 15] = create_witness(biguint_from_hex_le(
            "bca91cf9df6cfd8bd225fd3f46ba2f3f33809d0ee2e7ad338448b4ece7b4f622",
        ));

        // Invalidate witness
        witness[5][0] += PallasField::one();

        // gates[0] is ForeignMul0
        assert_eq!(
            cs.gates[0].verify_foreign_mul(0, &witness, &cs),
            Err(String::from("Invalid ForeignMul0 constraint"))
        );

        let mut witness: [Vec<PallasField>; 15] = create_witness(biguint_from_hex_le(
            "301a091e9f74cd459a448c311ae47fe2f4311db61ae1cbd2afee0171e2b5ca22",
        ));

        // Invalidate witness
        witness[8][0] = witness[0][0] + PallasField::one();

        // gates[0] is ForeignMul0
        assert_eq!(
            cs.gates[0].verify_foreign_mul(0, &witness, &cs),
            Err(String::from("Invalid ForeignMul0 constraint"))
        );
    }

    #[test]
    fn verify_foreign_mul1_valid_witness() {
        let cs = create_test_constraint_system();

        let witness: [Vec<PallasField>; 15] = create_witness(biguint_from_hex_le(
            "72de0b593fbd97e172ddfb1d7c1f7488948c622a7ff6bffa0279e35a7c148733",
        ));

        // gates[2] is ForeignMul1
        assert_eq!(cs.gates[2].verify_foreign_mul(2, &witness, &cs), Ok(()));

        let witness: [Vec<PallasField>; 15] = create_witness(biguint_from_hex_le(
            "58372fb93039e7106c68488dceb6cab3ffb0e7c8594dcc3bc7160321fcf6960d",
        ));

        // gates[2] is ForeignMul1
        assert_eq!(cs.gates[2].verify_foreign_mul(2, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_foreign_mul1_invalid_witness() {
        let cs = create_test_constraint_system();

        let mut witness: [Vec<PallasField>; 15] = create_witness(biguint_from_hex_le(
            "260efa1879427b08ca608d455d9f39954b5243dd52117e9ed5982f94acd3e22c",
        ));

        // Corrupt witness
        witness[0][2] = witness[7][2];

        // gates[2] is ForeignMul1
        assert_eq!(
            cs.gates[2].verify_foreign_mul(2, &witness, &cs),
            Err(String::from("Invalid ForeignMul1 constraint"))
        );

        let mut witness: [Vec<PallasField>; 15] = create_witness(biguint_from_hex_le(
            "afd209d02c77546022ea860f9340e4289ecdd783e9c0012fd383dcd2940cd51b",
        ));

        // Corrupt witness
        witness[13][2] = witness[1][2];

        // gates[2] is ForeignMul1
        assert_eq!(
            cs.gates[2].verify_foreign_mul(2, &witness, &cs),
            Err(String::from("Invalid ForeignMul1 constraint"))
        );
    }

    #[test]
    fn verify_foreign_mul2_valid_witness() {
        let _cs = create_test_constraint_system();

        let _witness: [Vec<PallasField>; 15] = create_witness(biguint_from_hex_le(
            "1aed1a6bc2ca84ee6edaedea4eb9b623392d24f64dfb0a8134ff16289bfc3c1f",
        ));

        // gates[3] is ForeignMul2 (cannot validate until plookup is implemented)
        // assert_eq!(cs.gates[3].verify_foreign_mul(3, &witness, &cs), Ok(()));

        let _witness: [Vec<PallasField>; 15] = create_witness(biguint_from_hex_le(
            "fd944d6dad12b5398bd2901b92439c6af31eca1766a1915bcd611df90830b508",
        ));

        // gates[3] is ForeignMul2 (cannot validate until plookup is implemented)
        // assert_eq!(cs.gates[3].verify_foreign_mul(3, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_foreign_mul2_invalid_witness() {
        let _cs = create_test_constraint_system();

        let mut witness: [Vec<PallasField>; 15] = create_witness(biguint_from_hex_le(
            "56acede83576c45ec8c11a85ac97e2393a9f88308b4b42d1b1506f2faaafc02b",
        ));

        // Corrupt witness
        witness[12][2] = witness[2][2];

        // gates[3] is ForeignMul2 (cannot validate until plookup is implemented)
        // assert_eq!(cs.gates[3].verify_foreign_mul(3, &witness, &cs), Ok(()));

        let mut witness: [Vec<PallasField>; 15] = create_witness(biguint_from_hex_le(
            "56acede83576c45ec8c11a85ac97e2393a9f88308b4b42d1b1506f2faaafc02b",
        ));

        // Corrupt witness
        witness[6][2] = witness[3][2];

        // gates[3] is ForeignMul2 (cannot validate until plookup is implemented)
        // assert_eq!(cs.gates[3].verify_foreign_mul(3, &witness, &cs), Ok(()));
    }
}
