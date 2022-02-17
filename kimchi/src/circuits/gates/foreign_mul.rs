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
//    Foreign field element are comprised of 3 88-bit limbs L0L1L2 such that
//
//      L0 = L0p0L0p1L0p2L0p3L0p4L0p5L0c0L0c1L0c2L0c3L0c4L0c5L0c6L0c7
//      L1 = L1p0L1p1L1p2L1p3L1p4L1p5L1c0L1c1L1c2L1c3L1c4L1c5L1c6L1c7
//      L2 = L2p0L2p1L2p2L2p3L2c0L2c1L2c2L2c3L2c4L2c5L2c6L2c7L2c8L2c9L2c10L2c11L2c12L2c13L2c14L2c15L2c16L2c17L2c18L2c19
//
//    where Xpi is the ith 12-bit chunk of X and Xci is the ith 2-bit crumb of X.
//
//          Rows -->
//          0              1              2              3
//   C  0 | L0           | L1             L2
//   o  1 | plookup L0p0 | plookup L1p0 | plookup L2p0 | plookup L0p4
//   l  2 | plookup L0p1 | plookup L1p1 | plookup L2p1 | plookup L0p5
//   s  3 | plookup L0p2 | plookup L1p2 | plookup L2p2 | plookup L1p4
//   |  4 | plookup L0p3 | plookup L1p3 | plookup L2p3 | plookup L1p5
//  \ / 5 | copy L0p4    | copy L1p4    | crumb L2c0   | crumb L2c10
//   '  6 | copy L0p5    | copy L1p5    | crumb L2c1   | crumb L2c11
//      7 | crumb L0c0   | crumb L1c0   | crumb L2c2   | crumb L2c12
//      8 | crumb L0c1   | crumb L1c1   | crumb L2c3   | crumb L2c13
//      9 | crumb L0c2   | crumb L1c2   | crumb L2c4   | crumb L2c14
//     10 | crumb L0c3   | crumb L1c3   | crumb L2c5   | crumb L2c15
//     11 | crumb L0c4   | crumb L1c4   | crumb L2c6   | crumb L2c16
//     12 | crumb L0c5   | crumb L1c5   | crumb L2c7   | crumb L2c17
//     13 | crumb L0c6   | crumb L1c6   | crumb L2c8   | crumb L2c18
//     14 | crumb L0c7   | crumb L1c7   | crumb L2c9   | crumb L2c19
//
//    The 12-bit chunks are constrained with plookups and the 2-bit crumbs constrained with
//    degree-4 constraints of the form x*(x - 1)*(x - 2)*(x - 3)

use crate::alphas::{self, ConstraintType};
use crate::circuits::constraints::ConstraintSystem;
use crate::circuits::expr::{self, Column, E};
use crate::circuits::gate::{CircuitGate, CurrOrNext::Curr, GateType};
use crate::circuits::polynomials;
use crate::circuits::scalars::ProofEvaluations;
use crate::circuits::wires::{GateWires, COLUMNS};
use ark_ff::{FftField, Zero};
use array_init::array_init;
use rand::prelude::StdRng;
use rand::SeedableRng;

pub const CIRCUIT_GATE_COUNT: usize = 3;

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
                wires: wires[1],
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

        // Combine constraints with per foreign mul CircuiteGate selectors
        let mut expr = E::zero(); // would like E::default();
        let selector_index = |g: GateType| E::cell(Column::Index(g), Curr);
        for (gate_type, constraints) in polynomials::foreign_mul::circuit_gates::<F>() {
            println!(
                "Creating expr for {:?} of {} constraints",
                gate_type,
                constraints.len()
            );
            expr += selector_index(gate_type)
                * E::combine_constraints(alphas.clone().take(constraints.len()), constraints);
        }

        // Linearize
        let linearized = expr.linearize(evaluated_cols).unwrap();

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

#[cfg(test)]
mod tests {
    use crate::circuits::{
        constraints::ConstraintSystem, expr::PolishToken, gate::CircuitGate, polynomial::COLUMNS,
        wires::Wire,
    };

    use ark_ec::AffineCurve;
    use ark_ff::PrimeField;
    use array_init::array_init;
    use mina_curves::pasta::{pallas, vesta};
    use num_bigint::BigUint;

    type PallasField = <pallas::Affine as AffineCurve>::BaseField;
    type VestaField = <vesta::Affine as AffineCurve>::BaseField;

    const LIMB_SIZE: usize = 88;

    struct Polish(Vec<PolishToken<PallasField>>);
    impl std::fmt::Display for Polish {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "[")?;
            for x in self.0.iter() {
                match x {
                    PolishToken::Literal(a) => write!(f, "{}, ", a)?,
                    PolishToken::Add => write!(f, "+, ")?,
                    PolishToken::Mul => write!(f, "*, ")?,
                    PolishToken::Sub => write!(f, "-, ")?,
                    x => write!(f, "{:?}, ", x)?,
                }
            }
            write!(f, "]")?;
            Ok(())
        }
    }

    fn limb_to_plookup_sublimb<F: PrimeField>(fe: F, col: usize) -> F {
        // TODO:
        let mut bytes: Vec<u8> = vec![];
        fe.serialize(&mut bytes)
            .expect("failed to serialize field element");

        println!("bytes {} = {:?}", bytes.len(), bytes);
        let _offset = (col - 1) * 12;
        bytes[1] &= 0xf0;
        for i in 2..bytes.len() {
            bytes[i] = 0;
        }

        F::deserialize(&bytes[..]).expect("failed to deserialize field element")
    }

    fn limb_to_crumb_sublimb<F: PrimeField>(fe: F, _col: usize) -> F {
        // TODO:
        fe
    }

    fn field_element_to_witness<F: PrimeField>(fe: BigUint) -> [Vec<F>; COLUMNS] {
        let mut rows: [Vec<F>; COLUMNS] = array_init(|_| vec![F::zero(); 4]);
        for (row, limb) in fe.to_bytes_le().chunks(LIMB_SIZE / 8 + 1).enumerate() {
            // Convert chunk to field element and store in column 0
            let mut bytes = limb.to_vec();
            bytes.append(&mut vec![0u8; F::size_in_bits() / 8 - limb.len() + 1]); // zero pad
            rows[0][row] = F::deserialize(&bytes[..]).expect("failed to deserialize field element");

            // Decompose limb into sublimbs and store in columns 1..COLUMNS
            for col in 1..7 {
                rows[col][row] = limb_to_plookup_sublimb(rows[0][row], col);
            }
            for col in 1..COLUMNS {
                rows[col][row] = limb_to_crumb_sublimb(rows[0][row], col);
            }
        }
        rows
    }

    #[test]
    fn create() {
        let wires = array_init(|i| Wire::new(i));
        let _x = CircuitGate::<PallasField>::create_foreign_mul(&wires);
    }

    #[test]
    fn verify_foreign_mul0_zero_witness() {
        let wires = array_init(|i| Wire::new(i));
        let gates = CircuitGate::<PallasField>::create_foreign_mul(&wires);

        let cs = ConstraintSystem::create(
            gates,
            vec![],
            oracle::pasta::fp::params(),
            o1_utils::packed_modulus::<PallasField>(o1_utils::get_modulus::<VestaField>()),
            0,
        )
        .unwrap();

        let witness: [Vec<PallasField>; COLUMNS] = array_init(|_| vec![PallasField::from(0); 2]);

        assert_eq!(cs.gates[0].verify_foreign_mul(0, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_foreign_mul0_one_witness() {
        let wires = array_init(|i| Wire::new(i));
        let gates = CircuitGate::<PallasField>::create_foreign_mul(&wires);

        let cs = ConstraintSystem::create(
            gates,
            vec![],
            oracle::pasta::fp::params(),
            o1_utils::packed_modulus::<PallasField>(o1_utils::get_modulus::<VestaField>()),
            0,
        )
        .unwrap();

        let witness: [Vec<PallasField>; COLUMNS] = array_init(|_| vec![PallasField::from(1); 2]);

        assert_eq!(
            cs.gates[0].verify_foreign_mul(0, &witness, &cs),
            Err("Invalid ForeignMul0 constraint".to_string())
        );
    }

    #[test]
    fn verify_foreign_mul0_valid_witness() {
        let wires = array_init(|i| Wire::new(i));
        let gates = CircuitGate::<PallasField>::create_foreign_mul(&wires);

        let cs = ConstraintSystem::create(
            gates,
            vec![],
            oracle::pasta::fp::params(),
            o1_utils::packed_modulus::<PallasField>(o1_utils::get_modulus::<VestaField>()),
            0,
        )
        .unwrap();

        let witness = field_element_to_witness(BigUint::from(31459u64));

        println!();
        println!("witness = {:?}", witness);
        println!();

        // TODO: WIP
        assert_eq!(
            cs.gates[0].verify_foreign_mul(0, &witness, &cs),
            Err("Invalid ForeignMul0 constraint".to_string())
        );
    }
}
