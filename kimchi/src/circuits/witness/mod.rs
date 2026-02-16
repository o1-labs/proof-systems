use ark_ff::{Field, PrimeField};

mod constant_cell;
mod copy_bits_cell;
mod copy_cell;
mod copy_shift_cell;
mod index_cell;
mod variable_bits_cell;
mod variable_cell;
mod variables;

pub use self::{
    constant_cell::ConstantCell,
    copy_bits_cell::CopyBitsCell,
    copy_cell::CopyCell,
    copy_shift_cell::CopyShiftCell,
    index_cell::IndexCell,
    variable_bits_cell::VariableBitsCell,
    variable_cell::VariableCell,
    variables::{variable_map, variables, Variables},
};

use super::polynomial::COLUMNS;

/// Witness cell interface. By default, the witness cell is a single element of type F.
pub trait WitnessCell<F: Field, T = F, const W: usize = COLUMNS> {
    fn value(&self, witness: &mut [Vec<F>; W], variables: &Variables<T>, index: usize) -> F;

    // Length is 1 by default (T is single F element) unless overridden
    fn length(&self) -> usize {
        1
    }
}

/// Initialize a witness cell based on layout and computed variables
/// Inputs:
/// - witness: the witness to initialize with values
/// - offset: the row offset of the witness before initialization
/// - row: the row index inside the partial layout
/// - col: the column index inside the witness
/// - cell: the cell index inside the partial layout (for any but IndexCell, it must be the same as col)
/// - index: the index within the variable (for IndexCell, 0 otherwise)
/// - layout: the partial layout to initialize from
/// - variables: the hashmap of variables to get the values from
#[allow(clippy::too_many_arguments)]
pub fn init_cell<F: PrimeField, T, const W: usize>(
    witness: &mut [Vec<F>; W],
    offset: usize,
    row: usize,
    col: usize,
    cell: usize,
    index: usize,
    layout: &[Vec<Box<dyn WitnessCell<F, T, W>>>],
    variables: &Variables<T>,
) {
    witness[col][row + offset] = layout[row][cell].value(witness, variables, index);
}

/// Initialize a witness row based on layout and computed variables
pub fn init_row<F: PrimeField, T, const W: usize>(
    witness: &mut [Vec<F>; W],
    offset: usize,
    row: usize,
    layout: &[Vec<Box<dyn WitnessCell<F, T, W>>>],
    variables: &Variables<T>,
) {
    let mut col = 0;
    for cell in 0..layout[row].len() {
        // The loop will only run more than once if the cell is an IndexCell
        for index in 0..layout[row][cell].length() {
            init_cell(witness, offset, row, col, cell, index, layout, variables);
            col += 1;
        }
    }
}

/// Initialize a witness based on layout and computed variables
pub fn init<F: PrimeField, T, const W: usize>(
    witness: &mut [Vec<F>; W],
    offset: usize,
    layout: &[Vec<Box<dyn WitnessCell<F, T, W>>>],
    variables: &Variables<T>,
) {
    for row in 0..layout.len() {
        init_row(witness, offset, row, layout, variables);
    }
}

#[cfg(test)]
mod tests {
    use core::array;

    use super::*;

    use crate::circuits::polynomial::COLUMNS;
    use ark_ec::AffineRepr;
    use ark_ff::{Field, One, Zero};
    use mina_curves::pasta::Pallas;
    type PallasField = <Pallas as AffineRepr>::BaseField;

    #[test]
    fn zero_layout() {
        let layout: Vec<Vec<Box<dyn WitnessCell<PallasField>>>> = vec![vec![
            ConstantCell::create(PallasField::zero()),
            ConstantCell::create(PallasField::zero()),
            ConstantCell::create(PallasField::zero()),
            ConstantCell::create(PallasField::zero()),
            ConstantCell::create(PallasField::zero()),
            ConstantCell::create(PallasField::zero()),
            ConstantCell::create(PallasField::zero()),
            ConstantCell::create(PallasField::zero()),
            ConstantCell::create(PallasField::zero()),
            ConstantCell::create(PallasField::zero()),
            ConstantCell::create(PallasField::zero()),
            ConstantCell::create(PallasField::zero()),
            ConstantCell::create(PallasField::zero()),
            ConstantCell::create(PallasField::zero()),
            ConstantCell::create(PallasField::zero()),
        ]];

        let mut witness: [Vec<PallasField>; COLUMNS] =
            array::from_fn(|_| vec![PallasField::one(); 1]);

        for col in witness.clone() {
            for field in col {
                assert_eq!(field, PallasField::one());
            }
        }

        // Set a single cell to zero
        init_cell(&mut witness, 0, 0, 4, 4, 0, &layout, &variables!());
        assert_eq!(witness[4][0], PallasField::zero());

        // Set all the cells to zero
        init_row(&mut witness, 0, 0, &layout, &variables!());

        for col in witness {
            for field in col {
                assert_eq!(field, PallasField::zero());
            }
        }
    }

    #[test]
    fn mixed_layout() {
        let layout: Vec<Vec<Box<dyn WitnessCell<PallasField>>>> = vec![
            vec![
                ConstantCell::create(PallasField::from(12u32)),
                ConstantCell::create(PallasField::from(0xa5a3u32)),
                ConstantCell::create(PallasField::from(0x800u32)),
                CopyCell::create(0, 0),
                CopyBitsCell::create(0, 1, 0, 4),
                CopyShiftCell::create(0, 2, 12),
                VariableCell::create("sum_of_products"),
                ConstantCell::create(PallasField::zero()),
                ConstantCell::create(PallasField::zero()),
                ConstantCell::create(PallasField::zero()),
                ConstantCell::create(PallasField::zero()),
                ConstantCell::create(PallasField::zero()),
                ConstantCell::create(PallasField::zero()),
                ConstantCell::create(PallasField::zero()),
                ConstantCell::create(PallasField::zero()),
            ],
            vec![
                CopyCell::create(0, 0),
                CopyBitsCell::create(0, 1, 4, 8),
                CopyShiftCell::create(0, 2, 8),
                VariableCell::create("sum_of_products"),
                ConstantCell::create(PallasField::zero()),
                ConstantCell::create(PallasField::zero()),
                ConstantCell::create(PallasField::zero()),
                VariableCell::create("something_else"),
                ConstantCell::create(PallasField::zero()),
                ConstantCell::create(PallasField::zero()),
                ConstantCell::create(PallasField::zero()),
                ConstantCell::create(PallasField::zero()),
                ConstantCell::create(PallasField::zero()),
                ConstantCell::create(PallasField::zero()),
                VariableCell::create("final_value"),
            ],
        ];

        let mut witness: [Vec<PallasField>; COLUMNS] =
            array::from_fn(|_| vec![PallasField::zero(); 2]);

        // Local variable (witness computation) with same names as VariableCell above
        let sum_of_products = PallasField::from(1337u32);
        let something_else = sum_of_products * PallasField::from(5u32);
        let final_value = (something_else + PallasField::one()).pow([2u64]);

        init_row(
            &mut witness,
            0,
            0,
            &layout,
            &variables!(sum_of_products, something_else, final_value),
        );

        assert_eq!(witness[3][0], PallasField::from(12u32));
        assert_eq!(witness[4][0], PallasField::from(0x3u32));
        assert_eq!(witness[5][0], PallasField::from(0x800000u32));
        assert_eq!(witness[6][0], sum_of_products);

        init_row(
            &mut witness,
            0,
            1,
            &layout,
            &variables!(sum_of_products, something_else, final_value),
        );

        assert_eq!(witness[0][1], PallasField::from(12u32));
        assert_eq!(witness[1][1], PallasField::from(0xau32));
        assert_eq!(witness[2][1], PallasField::from(0x80000u32));
        assert_eq!(witness[3][1], sum_of_products);
        assert_eq!(witness[7][1], something_else);
        assert_eq!(witness[14][1], final_value);

        let mut witness2: [Vec<PallasField>; COLUMNS] =
            array::from_fn(|_| vec![PallasField::zero(); 2]);
        init(
            &mut witness2,
            0,
            &layout,
            &variables!(sum_of_products, something_else, final_value),
        );

        for row in 0..witness[0].len() {
            for col in 0..witness.len() {
                assert_eq!(witness[col][row], witness2[col][row]);
            }
        }
    }
}
