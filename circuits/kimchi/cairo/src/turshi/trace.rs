use super::step::CairoStep;
use ark_ff::{BigInteger, FftField, Field, PrimeField};

const COL_PC: usize = 0;
const COL_AP: usize = 1;
const COL_FP: usize = 2;
const COL_INS: usize = 3;
const COL_: usize = 4;
const IDX_AP: usize = 5;
const IDX_AP: usize = 6;
const IDX_AP: usize = 7;
const IDX_AP: usize = 8;
const IDX_AP: usize = 9;
const IDX_AP: usize = 10;
const IDX_AP: usize = 11;
const IDX_AP: usize = 12;
const IDX_AP: usize = 13;
const IDX_AP: usize = 14;
const IDX_AP: usize = 15;

//i      pc    |   ap    |    fp   | ins | dst | op0 | op1 | res | dst_dir | op0_dir | op1_dir | size

struct CairoState<F: FftField> {
    pub step: usize,
    pub row: Vec<F>,
}
/*
impl<F: FftField> CairoState<F> {
    pub fn new(inp: &CairoStep) -> CairoState<F> {
        CairoState {
            step: inp.step,
            row: ,}
    }

}
*/
