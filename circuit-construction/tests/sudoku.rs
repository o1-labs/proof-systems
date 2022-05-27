//! Sudoku test
//! It'd be nice if we could write it like https://github.com/o1-labs/snarkyjs/blob/8464704b60/src/examples/sudoku/sudoku-zkapp.ts#L47

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{FftField, Field, PrimeField, UniformRand};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
use circuit_construction::*;
use commitment_dlog::{commitment::CommitmentCurve, srs::SRS};
use groupmap::GroupMap;
use kimchi::{
    circuits::{
        gate::GateType, polynomial::COLUMNS, polynomials::generic::GENERIC_COEFFS, wires::GateWires,
    },
    verifier::verify,
};
use mina_curves::pasta::{
    fp::Fp,
    fq::Fq,
    pallas::{Affine as Other, PallasParameters},
    vesta::{Affine, VestaParameters},
};
use o1_utils::types::fields::*;
use oracle::{
    constants::*,
    poseidon::{ArithmeticSponge, Sponge},
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use std::{collections::HashMap, sync::Arc};

type SpongeQ = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
type SpongeR = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;

/// A solution is the full thing
const PUBLIC_INPUT_LENGTH: usize = 9 * 9;

//
// Sudoku made out of field elements
//

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
            vec![5, 3, e, /* */ e, 7, e, /* */ e, e, e],
            vec![6, e, e, /* */ 1, 9, 5, /* */ e, e, e],
            vec![e, 9, 8, /* */ e, e, e, /* */ e, 6, e],
            /* -------------------------------------- */
            vec![8, e, e, /* */ e, 6, e, /* */ e, e, 3],
            vec![4, e, e, /* */ 8, e, 3, /* */ e, e, 1],
            vec![7, e, e, /* */ e, 2, e, /* */ e, e, 6],
            /* -------------------------------------- */
            vec![e, 6, e, /* */ e, e, e, /* */ 2, 8, e],
            vec![e, e, e, /* */ 4, 1, 9, /* */ e, e, 5],
            vec![e, e, e, /* */ e, 8, e, /* */ e, 7, 9],
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
            vec![5, 3, 4, /* */ 6, 7, 8, /* */ 9, 1, 2],
            vec![6, 7, 2, /* */ 1, 9, 5, /* */ 3, 4, 8],
            vec![1, 9, 8, /* */ 3, 4, 2, /* */ 5, 6, 7],
            /* -------------------------------------- */
            vec![8, 5, 9, /* */ 7, 6, 1, /* */ 4, 2, 3],
            vec![4, 2, 6, /* */ 8, 5, 3, /* */ 7, 9, 1],
            vec![7, 1, 3, /* */ 9, 2, 4, /* */ 8, 5, 6],
            /* -------------------------------------- */
            vec![9, 6, 1, /* */ 5, 3, 7, /* */ 2, 8, 4],
            vec![2, 8, 7, /* */ 4, 1, 9, /* */ 6, 3, 5],
            vec![3, 4, 5, /* */ 2, 8, 6, /* */ 1, 7, 9],
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

//
// Sudoku made out of vars
//

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

        /*
        let mut check_vars = |vars: &[Var<F>]| {
            for num in 0..9u32 {
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
            .zip(8..=0)
            .map(|(row, idx)| row[idx])
            .collect();
        check_vars(&other_diag);

        // assert
        sys.assert_eq(res, one);
        */

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
    // parse public sudoku
    let sudoku = SudokuVar::from_public_input(sys, public_input);

    // parse witness
    let witness = SudokuVar::from_witness(sys, witness);

    // reconstruct full sudoku
    let mut rows = vec![];
    for row in 0..9 {
        let mut column = vec![];
        for col in 0..9 {
            let is_empty = sudoku.is_empty(sys, row, col);
            let cell = sudoku.get(row, col);
            let solved = witness.get(row, col);
            //let val = sys.cond_select(is_empty, solved, cell);
            //column.push(val);
            column.push(cell);
        }
        rows.push(column);
        break;
    }

    //let sudoku = SudokuVar(rows);

    //sudoku.debug(sys);

    /*
    // 2. verify it
    sudoku.verify(sys);
    */

    // 3. add zk
    //sys.zk()
}

//
// Test
//

#[test]
fn test_sudoku() {
    // generate SRS
    let srs = {
        let mut srs = SRS::<Affine>::create(1 << 10);
        srs.add_lagrange_basis(D::new(256).unwrap());
        Arc::new(srs)
    };

    // generate sudoku + solution for example
    let sudoku = Sudoku::<BaseField<Other>>::new_problem();
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
