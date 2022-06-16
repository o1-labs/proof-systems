//! Sudoku test
//! It'd be nice if we could write it like https://github.com/o1-labs/snarkyjs/blob/8464704b60/src/examples/sudoku/sudoku-zkapp.ts#L47

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{FftField, Field, PrimeField, UniformRand};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
use circuit_construction::*;
use commitment_dlog::{commitment::CommitmentCurve, srs::SRS};
use groupmap::GroupMap;
use kimchi::verifier::verify;
use mina_curves::pasta::{
    fp::Fp,
    fq::Fq,
    pallas::{Affine as Other, PallasParameters},
    vesta::{Affine, VestaParameters},
};
use oracle::{
    constants::*,
    poseidon::{ArithmeticSponge, Sponge},
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use std::{collections::HashMap, sync::Arc};

type SpongeQ = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
type SpongeR = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;

/// -1 means not filled in
#[derive(Clone)]
pub struct Sudoku<F>(Vec<Vec<F>>);

impl<F> Sudoku<F>
where
    F: Field,
{
    pub fn new_problem() -> Self {
        let from = |a: i32| {
            if a > 0 {
                F::from(a as u32)
            } else {
                -F::from(a.abs() as u32)
            }
        };
        let e = -1;
        let data: Vec<Vec<i32>> = vec![
            vec![e, 4, e, /* */ 3, e, e, /* */ e, 8, e],
            vec![e, e, 3, /* */ 5, e, 2, /* */ e, 4, e],
            vec![e, e, e, /* */ e, e, 1, /* */ 5, e, 3],
            /* -------------------------------------- */
            vec![e, e, 2, /* */ 4, e, e, /* */ 1, e, e],
            vec![4, e, e, /* */ e, 2, e, /* */ e, e, 7],
            vec![e, e, 7, /* */ e, e, 3, /* */ 8, e, e],
            /* -------------------------------------- */
            vec![1, e, 8, /* */ 2, e, e, /* */ e, e, e],
            vec![e, 7, e, /* */ 1, e, 8, /* */ 4, e, e],
            vec![e, 2, e, /* */ e, e, 9, /* */ e, 1, e],
        ];
        let mut res = vec![];
        for row in data {
            res.push(row.into_iter().map(from).collect());
        }
        Self(res)
    }

    pub fn solution() -> Self {
        let from = |a: i32| {
            if a > 0 {
                F::from(a as u32)
            } else {
                -F::from(a.abs() as u32)
            }
        };
        let e = -1;
        let data: Vec<Vec<i32>> = vec![
            vec![6, 4, 5, /* */ 3, 9, 7, /* */ 2, 8, 1],
            vec![7, 1, 3, /* */ 5, 8, 2, /* */ 9, 4, 6],
            vec![2, 8, 9, /* */ 6, 4, 1, /* */ 5, 7, 3],
            /* -------------------------------------- */
            vec![8, 3, 2, /* */ 4, 7, 6, /* */ 1, 9, 5],
            vec![4, 9, 1, /* */ 8, 2, 5, /* */ 3, 6, 7],
            vec![5, 6, 7, /* */ 9, 1, 3, /* */ 8, 2, 4],
            /* -------------------------------------- */
            vec![1, 5, 8, /* */ 2, 6, 4, /* */ 7, 3, 9],
            vec![9, 7, 6, /* */ 1, 3, 8, /* */ 4, 5, 2],
            vec![3, 2, 4, /* */ 7, 5, 9, /* */ 6, 1, 8],
        ];
        let mut res = vec![];
        for row in data {
            res.push(row.into_iter().map(from).collect());
        }
        Self(res)
    }

    fn get(&self, row: usize, col: usize) -> F {
        self.0[row][col]
    }

    fn is_empty(&self, row: usize, col: usize) -> bool {
        self.get(row, col) == -F::one()
    }

    fn flatten(&self) -> Vec<F> {
        self.0.iter().flatten().copied().collect()
    }
}

/// A solution is the full thing
const PUBLIC_INPUT_LENGTH: usize = 9 * 9;

pub struct SudokuVar<F>(Vec<Vec<Var<F>>>);

impl<F> SudokuVar<F>
where
    F: PrimeField,
{
    fn get(&self, row: usize, col: usize) -> Var<F> {
        self.0[row][col]
    }

    fn is_empty<Sys>(&self, sys: &mut Sys, row: usize, col: usize) -> Var<F>
    where
        Sys: Cs<F>,
    {
        let minus_one = sys.constant(-F::one());
        sys.equals(self.get(row, col), minus_one)
    }

    fn from_public_input<Sys>(sys: &mut Sys, public_sudoku: Vec<Var<F>>) -> Self
    where
        Sys: Cs<F>,
    {
        let mut sudoku = vec![];
        for row in 0..9 {
            let mut column = vec![];
            for col in 0..9 {
                let cell = public_sudoku[row * 9 + col];
                column.push(cell);
            }
            sudoku.push(column);
        }

        Self(sudoku)
    }

    fn new<Sys>(sys: &mut Sys, public_sudoku: Vec<Var<F>>, witness: Option<&Sudoku<F>>) -> Self
    where
        Sys: Cs<F>,
    {
        // parse public sudoku
        let sudoku = Self::from_public_input(sys, public_sudoku);

        // parse witness
        let witness = Self::from_witness(sys, witness);

        // reconstruct full sudoku
        let mut thing = vec![];
        for row in 0..9 {
            let mut column = vec![];
            for col in 0..9 {
                let is_empty = sudoku.is_empty(sys, row, col);
                let cell = sudoku.get(row, col);
                let solved = witness.get(row, col);
                let val = sys.cond_select(is_empty, solved, cell);
                column.push(val);
            }
            thing.push(column);
        }

        Self(thing)
    }

    fn from_witness<Sys>(sys: &mut Sys, solution: Option<&Sudoku<F>>) -> Self
    where
        Sys: Cs<F>,
    {
        let mut sudoku = vec![];
        for row in 0..9 {
            let mut column = vec![];
            for col in 0..9 {
                let var = sys.var(|| solution.unwrap().get(row, col));
                column.push(var);
            }
            sudoku.push(column);
        }

        Self(sudoku)
    }

    fn verify<Sys>(&self, sys: &mut Sys)
    where
        Sys: Cs<F>,
    {
        // must return 1 at the end
        let one = sys.constant(F::one());
        let mut res = sys.constant(F::one());

        let mut check_vars = |vars: &[Var<F>]| {
            for num in 1..=9u32 {
                // must be 1 at the end
                let mut in_row = sys.constant(F::zero());
                let num = sys.constant(F::from(num));
                // TODO: bool type?
                for el in vars {
                    let eq = sys.equals(*el, num);
                    in_row = sys.cond_select(eq, one, in_row);
                }
                // res | in_row | new_res
                //  0  |   0    |   0
                //  1  |   0    |   0
                //  0  |   1    |   0
                //  1  |   1    |   1
                res = sys.cond_select(in_row, res, in_row);
            }
        };

        // rows
        for row in &self.0 {
            check_vars(row);
        }

        // cols
        for col in 0..9 {
            let list: Vec<_> = self.0.iter().map(|row| row[col]).collect();
            check_vars(&list);
        }

        // diagonals
        let diag: Vec<_> = self.0.iter().zip(0..).map(|(row, idx)| row[idx]).collect();
        check_vars(&diag);

        let other_diag: Vec<_> = self
            .0
            .iter()
            .zip((0..=8).rev())
            .map(|(row, idx)| row[idx])
            .collect();
        check_vars(&other_diag);

        // assert
        sys.assert_eq(res, one);

        // TODO: it's really a pain to do anything because there's no add, sub, etc. implemented on Var
    }

    fn debug<Sys>(&self, sys: &mut Sys)
    where
        Sys: Cs<F>,
    {
        let els: HashMap<_, _> = (1..=9u32).map(|i| (F::from(i), i)).collect();

        sys.debug(|| {
            for row in &self.0 {
                for col in row {
                    print!("| {}", els[&col.val()]);
                }
                println!(" |");
            }
        });
    }
}

//
// Main circuit
//

/// Prover can prove they know a solution to a public sudoku
pub fn sudoku_prove<F, G, Sys>(
    constants: &Constants<F>,
    // The witness
    witness: Option<&Sudoku<F>>,
    sys: &mut Sys,
    public_input: Vec<Var<F>>,
) where
    F: PrimeField + FftField,
    G: AffineCurve<BaseField = F> + CoordinateCurve,
    Sys: Cs<F>,
{
    // 1. reconstruct the sudoku
    let sudoku = SudokuVar::new(sys, public_input, witness);

    // 2. verify it
    sudoku.verify(sys);
}

#[test]
fn test_sudoku() {
    // generate SRS
    let srs = {
        let mut srs = SRS::<Affine>::create(1 << 14); // 2^8 = 256
        srs.add_lagrange_basis(D::new(srs.g.len()).unwrap());
        Arc::new(srs)
    };

    // generate sudoku + solution for example
    let sudoku = Sudoku::<<FpInner as Cycle>::InnerField>::new_problem();
    let solution = Sudoku::solution();

    // compile circuit
    let proof_system_constants = fp_constants();
    let fq_poseidon = oracle::pasta::fq_kimchi::params();
    let prover_index = generate_prover_index::<FpInner, _>(
        srs,
        &proof_system_constants,
        &fq_poseidon,
        PUBLIC_INPUT_LENGTH,
        |sys, p| sudoku_prove::<_, Other, _>(&proof_system_constants, None, sys, p),
    );

    // generate witness + proof
    let group_map = <Affine as CommitmentCurve>::Map::setup();
    let proof = prove::<Affine, _, SpongeQ, SpongeR>(
        &prover_index,
        &group_map,
        None,
        sudoku.flatten(),
        |sys, p| sudoku_prove::<Fp, Other, _>(&proof_system_constants, Some(&solution), sys, p),
    );

    // verify proof
    let verifier_index = prover_index.verifier_index();
    verify::<_, SpongeQ, SpongeR>(&group_map, &verifier_index, &proof).unwrap();
}
