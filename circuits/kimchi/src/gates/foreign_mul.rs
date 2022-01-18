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

use ark_ec::AffineCurve;
use array_init::array_init;
use mina_curves::pasta;

use crate::expr;
use crate::gate::{CircuitGate, GateType};
use crate::nolookup::{constraints::ConstraintSystem, foreign_moduli};
use crate::wires::{GateWires, COLUMNS};
use ark_ff::FftField;

type VestaBaseField = <pasta::vesta::Affine as AffineCurve>::BaseField;

const ROWS_PER_FIELD: usize = 4; // Rows per foreign field element

/// Foreign field element row-mapping helper
struct ForeignField<F: FftField> {
    rows: [[F; COLUMNS]; ROWS_PER_FIELD],
}

impl<F: FftField> ForeignField<F> {
    fn from(witness: &[Vec<F>; COLUMNS], row: usize) -> Self {
        ForeignField {
            rows: [
                array_init(|i| witness[i][row]),
                array_init(|i| witness[i][row + 1]),
                array_init(|i| witness[i][row + 2]),
                array_init(|i| witness[i][row + 3]),
            ],
        }
    }

    fn limb(&self, i: usize) -> F {
        assert!(i < 3);
        self.rows[i][0]
    }

    fn row(&self, i: usize) -> [F; COLUMNS] {
        self.rows[i]
    }
}

impl<F: FftField> CircuitGate<F> {
    /// Create vesta foreign multiplication gate
    pub fn create_foreign_mul(typ: GateType, wires: GateWires) -> Self {
        assert!(typ == GateType::ForeignMulPastaPallas || typ == GateType::ForeignMulPastaVesta);

        CircuitGate {
            typ,
            wires,
            c: vec![],
        }
    }

    pub fn verify_foreign_mul(
        &self,
        typ: GateType,
        row: usize,
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
    ) -> Result<(), String> {
        ensure_eq!(
            self.typ,
            typ,
            format!("incorrect gate type (should be {:?})", typ)
        );

        // Compute t such that 2^t*n > p^2 + p
        //     t = log2(p^2 - p) - log2(n) + 1

        let _constants = expr::Constants {
            alpha: F::zero(),
            beta: F::zero(),
            gamma: F::zero(),
            joint_combiner: F::zero(),
            mds: vec![],
            endo_coefficient: cs.endo,
            foreign_moduli: cs.foreign_moduli.clone(),
        };

        let a = ForeignField::from(witness, row);
        let _a0 = a.limb(0);
        let _row = a.row(0);

        let _foreign_mod = foreign_moduli::get_modulus::<F, VestaBaseField>();

        Ok(())
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
    use crate::{
        gate::{CircuitGate, GateType},
        gates::foreign_mul::ForeignField,
        polynomial::COLUMNS,
        wires::Wire,
    };

    use ark_ec::AffineCurve;
    use mina_curves::pasta::pallas;
    type PallasField = <pallas::Affine as AffineCurve>::BaseField;

    #[test]
    fn scratch() {
        let witness: [Vec<PallasField>; COLUMNS] = [
            vec![PallasField::from(0); 4],
            vec![PallasField::from(1); 4],
            vec![PallasField::from(2); 4],
            vec![PallasField::from(3); 4],
            vec![PallasField::from(4); 4],
            vec![PallasField::from(5); 4],
            vec![PallasField::from(6); 4],
            vec![PallasField::from(7); 4],
            vec![PallasField::from(8); 4],
            vec![PallasField::from(9); 4],
            vec![PallasField::from(10); 4],
            vec![PallasField::from(11); 4],
            vec![PallasField::from(12); 4],
            vec![PallasField::from(13); 4],
            vec![PallasField::from(14); 4],
        ];

        let _x = ForeignField::from(&witness, 0);
        println!("row[0]  = {:?}", _x.row(0));
        println!("limb(0) = {:?}", _x.limb(0));
    }

    #[test]
    fn vesta_on_pallas_test() {
        let _x = CircuitGate::<PallasField>::create_foreign_mul(
            GateType::ForeignMulPastaVesta,
            Wire::new(0),
        );
    }
}
