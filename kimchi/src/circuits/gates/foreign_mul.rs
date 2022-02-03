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

use crate::expr;
use crate::gate::{CircuitGate, GateType};
use crate::nolookup::constraints::ConstraintSystem;
use crate::polynomials::foreign_mul;
use crate::wires::{GateWires, COLUMNS};
use ark_ff::FftField;

pub const CIRCUIT_GATE_COUNT: usize = 2;

impl<F: FftField> CircuitGate<F> {
    /// Create vesta foreign multiplication gate
    pub fn create_foreign_mul(wires: GateWires) -> Self {
        /* input: a */
        CircuitGate {
            typ: GateType::ForeignMul0,
            wires,
            c: vec![],
        }
        // CircuitGate {
        //     typ: GateType::ForeignMul0,
        //     wires,
        //     c: vec![],
        // },
        // CircuitGate {
        //     typ: GateType::ForeignMul1,
        //     wires,
        //     c: vec![],
        // },
        // CircuitGate {
        //     typ: GateType::ForeignMul1,
        //     wires,
        //     c: vec![],
        // },
        // /* input: b */
        // CircuitGate {
        //     typ: GateType::ForeignMul0,
        //     wires,
        //     c: vec![],
        // },
        // CircuitGate {
        //     typ: GateType::ForeignMul0,
        //     wires,
        //     c: vec![],
        // },
        // CircuitGate {
        //     typ: GateType::ForeignMul1,
        //     wires,
        //     c: vec![],
        // },
        // CircuitGate {
        //     typ: GateType::ForeignMul1,
        //     wires,
        //     c: vec![],
        // },
    }

    pub fn verify_foreign_mul(
        &self,
        _row: usize,
        _witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
    ) -> Result<(), String> {
        ensure_eq!(self.typ, GateType::ForeignMul0, "incorrect gate type");

        let _constants = expr::Constants {
            alpha: F::zero(),
            beta: F::zero(),
            gamma: F::zero(),
            joint_combiner: F::zero(),
            mds: vec![],
            endo_coefficient: cs.endo,
            foreign_modulus: cs.foreign_modulus.clone(),
        };

        // Breadth first approach
        // Unit test from ground up (create a verify method in polynomials)
        // Use bigint lib to build test cases
        // Test code to check values

        let _constraints = foreign_mul::constraint::<F>(0 /* TODO: alpha */);

        Ok(())
    }

    pub fn foreign_mul(&self) -> F {
        if self.typ == GateType::ForeignMul0 {
            F::one()
        } else {
            F::zero()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        gate::CircuitGate, nolookup::constraints::ConstraintSystem, polynomial::COLUMNS,
        wires::Wire,
    };

    use ark_ec::AffineCurve;
    use mina_curves::pasta::{pallas, vesta};
    type PallasField = <pallas::Affine as AffineCurve>::BaseField;
    type VestaField = <vesta::Affine as AffineCurve>::BaseField;

    #[test]
    fn verify() {
        let gates = vec![
            CircuitGate::<PallasField>::create_foreign_mul(Wire::new(0)),
            CircuitGate::<PallasField>::create_foreign_mul(Wire::new(0)),
        ];

        let cs = ConstraintSystem::create(
            gates,
            vec![],
            oracle::pasta::fp::params(),
            o1_utils::packed_modulus::<PallasField, VestaField>(),
            0,
        )
        .unwrap();

        let witness: [Vec<PallasField>; COLUMNS] = [
            vec![PallasField::from(0); 8],
            vec![PallasField::from(1); 8],
            vec![PallasField::from(2); 8],
            vec![PallasField::from(3); 8],
            vec![PallasField::from(4); 8],
            vec![PallasField::from(5); 8],
            vec![PallasField::from(6); 8],
            vec![PallasField::from(7); 8],
            vec![PallasField::from(8); 8],
            vec![PallasField::from(9); 8],
            vec![PallasField::from(10); 8],
            vec![PallasField::from(11); 8],
            vec![PallasField::from(12); 8],
            vec![PallasField::from(13); 8],
            vec![PallasField::from(14); 8],
        ];

        let res = cs.gates[0].verify_foreign_mul(0, &witness, &cs);

        println!("res = {:?}", res);
    }

    #[test]
    fn create() {
        let _x = CircuitGate::<PallasField>::create_foreign_mul(Wire::new(0));
    }
}
