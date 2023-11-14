//! Keccak witness computation

use crate::circuits::witness::{IndexCell, WitnessCell};
use ark_ff::PrimeField;

use super::KECCAK_COLS;

type _Layout<F, const COLUMNS: usize> = Vec<Box<dyn WitnessCell<F, Vec<F>, COLUMNS>>>;

fn _layout_round<F: PrimeField>() -> _Layout<F, KECCAK_COLS> {
    vec![
        IndexCell::create("state_a", 0, 100),
        IndexCell::create("state_c", 100, 120),
        IndexCell::create("shifts_c", 120, 200),
        IndexCell::create("dense_c", 200, 220),
        IndexCell::create("quotient_c", 220, 240),
        IndexCell::create("remainder_c", 240, 260),
        IndexCell::create("bound_c", 260, 280),
        IndexCell::create("dense_rot_c", 280, 300),
        IndexCell::create("expand_rot_c", 300, 320),
        IndexCell::create("state_d", 320, 340),
        IndexCell::create("state_e", 340, 440),
        IndexCell::create("shifts_e", 440, 840),
        IndexCell::create("dense_e", 840, 940),
        IndexCell::create("quotient_e", 940, 1040),
        IndexCell::create("remainder_e", 1040, 1140),
        IndexCell::create("bound_e", 1140, 1240),
        IndexCell::create("dense_rot_e", 1240, 1340),
        IndexCell::create("expand_rot_e", 1340, 1440),
        IndexCell::create("state_b", 1440, 1540),
        IndexCell::create("shifts_b", 1540, 1940),
        IndexCell::create("shifts_sum", 1940, 2340),
        IndexCell::create("f00", 2340, 2344),
    ]
}

fn _layout_sponge<F: PrimeField>() -> _Layout<F, KECCAK_COLS> {
    vec![
        IndexCell::create("old_state", 0, 100),
        IndexCell::create("new_state", 100, 200),
        IndexCell::create("dense", 200, 300),
        IndexCell::create("bytes", 300, 500),
        IndexCell::create("shifts", 500, 900),
    ]
}
