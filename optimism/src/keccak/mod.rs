pub mod column;

pub const ZKVM_KECCAK_COLS: usize = 1965 + 6;
pub const RATE: usize = 1088;
pub const RATE_IN_BYTES: usize = RATE / 8;
pub const DIM: usize = 5;
pub const QUARTERS: usize = 4;

fn grid_index(size: usize, i: usize, y: usize, x: usize, q: usize) -> usize {
    match size {
        20 => q + QUARTERS * x,
        80 => q + QUARTERS * (x + DIM * i),
        100 => q + QUARTERS * (x + DIM * y),
        400 => q + QUARTERS * (x + DIM * (y + DIM * i)),
        _ => panic!("Invalid grid size"),
    }
}
