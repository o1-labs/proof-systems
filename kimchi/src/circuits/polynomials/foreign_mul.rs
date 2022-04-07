// Foreign field multiplication
//
// https://hackmd.io/XZUHHGpDQsSOs0dUGugB5w
//
// Globals:
//     * n: native field modulus
//     * p: foreign field modulus
//
// Inputs:
//     * a: left foreign field element operand a \in Fp
//     * b: right foreign field element operand b \in Fp
//
// Witness:
//     * q: \in Fp
//     * r: such that a*b = q*p +r
//
// Foreign field element structure:
//
//    Each foreign field element a is decomposed into three 88-bit limbs a0, a1, a2 s.t. a = a0a1a2 in
//    little-endian byte order (i.e. a = a2*2^{2b} + a1*2^b + a0)
//      a0 = a0p0a0p1a0p2a0p3a0p4a0p5a0c0a0c1a0c2a0c3a0c4a0c5a0c6a0c7
//      a1 = a1p0a1p1a1p2a1p3a1p4a1p5a1c0a1c1a1c2a1c3a1c4a1c5a1c6a1c7
//      a2 = a2p0a2p1a2p2a2p3a2c0a2c1a2c2a2c3a2c4a2c5a2c6a2c7a2c8a2c9a2c10a2c11a2c12a2c13a2c14a2c15a2c16a2c17a2c18a2c19
//
//    where
//      * aXpi is a 12-bit sublimb of limb aX
//      * aXci is a 2-bit "crumb" sublimb of aX
//
// Input structure:
//
//   Row*  Contents**
//     0   a0
//     1   a1
//     2   a2
//     3   a0,a1,a2
//     4   b0
//     5   b1
//     6   b2
//     7   b0,b1,b2
//
//    (*)  Row offsets
//    (**) Some part of the limb is contained in this row
//
// Constraints:
//
//   For efficiency, the foreign field element inputs are constrained
//   by their sublimbs according to their type.
//     * 12-bit sublimbs are constrained with plookups
//     * 2-bit crumbs are constrained with degree-4 constraints
//
// Example:
//
//   This example shows how input a is constrained
//
//          Rows -->
//          0              1              2              3
//   C  0 | a0           | a1             a2
//   o  1 | plookup a0p0 | plookup a1p0 | plookup a2p0 | plookup a0p4
//   l  2 | plookup a0p1 | plookup a1p1 | plookup a2p1 | plookup a0p5
//   s  3 | plookup a0p2 | plookup a1p2 | plookup a2p2 | plookup a1p4
//   |  4 | plookup a0p3 | plookup a1p3 | plookup a2p3 | plookup a1p5
//  \ / 5 | copy a0p4    | copy a1p4    | crumb a2c0   | crumb a2c10
//   '  6 | copy a0p5    | copy a1p5    | crumb a2c1   | crumb a2c11
//      7 | crumb a0c0   | crumb a1c0   | crumb a2c2   | crumb a2c12
//      8 | crumb a0c1   | crumb a1c1   | crumb a2c3   | crumb a2c13
//      9 | crumb a0c2   | crumb a1c2   | crumb a2c4   | crumb a2c14
//     10 | crumb a0c3   | crumb a1c3   | crumb a2c5   | crumb a2c15
//     11 | crumb a0c4   | crumb a1c4   | crumb a2c6   | crumb a2c16
//     12 | crumb a0c5   | crumb a1c5   | crumb a2c7   | crumb a2c17
//     13 | crumb a0c6   | crumb a1c6   | crumb a2c8   | crumb a2c18
//     14 | crumb a0c7   | crumb a1c7   | crumb a2c9   | crumb a2c19
//
//          ForeignMul0    ForeignMul0    ForeignMul1    ForeignMul2  <-- Gate type of row
//
//    The 12-bit chunks are constrained with plookups and the 2-bit crumbs constrained with
//    degree-4 constraints of the form x*(x - 1)*(x - 2)*(x - 3)
//
// Gate types:
//
//   Different rows are constrained differently using different CircuitGate types
//
//   Row   CircuitGate   Purpose
//     0   ForeignMul0   Constrain a
//     1   ForeignMul0       "
//     2   ForeignMul1       "
//     3   ForeignMul2       "
//     4   ForeignMul0   Constrain b
//     5   ForeignMul0       "
//     6   ForeignMul1       "
//     7   ForeignMul2       "
//
//   Nb. each CircuitGate type corresponds to a unique polynomial and thus
//        is assigned its own unique powers of alpha

use array_init::array_init;
use num_bigint::BigUint;
use o1_utils::FieldHelpers;
use rand::prelude::StdRng;
use rand::SeedableRng;
use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;

use crate::alphas::Alphas;
use crate::circuits::argument::{Argument, ArgumentType};
use crate::circuits::constraints::ConstraintSystem;
use crate::circuits::expr;
use crate::circuits::gate::CircuitGate;
use crate::circuits::wires::GateWires;
use crate::{
    circuits::{
        expr::{Cache, Column, ConstantExpr, Expr, PolishToken, E},
        gate::{CurrOrNext, GateType},
        polynomial::COLUMNS,
    },
    proof::ProofEvaluations,
};

use ark_ff::{FftField, One, PrimeField, Zero};
use CurrOrNext::*;

struct Polish<F>(Vec<PolishToken<F>>);
impl<F: FftField> Display for Polish<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
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

pub const CIRCUIT_GATE_COUNT: usize = 3;

const MAX_LIMBS: usize = 3;
const LIMB_SIZE: usize = 88;

fn gate_type_to_selector<F: FftField>(typ: GateType) -> Option<[F; CIRCUIT_GATE_COUNT]> {
    match typ {
        GateType::ForeignMul0 => Some([F::one(), F::zero(), F::zero()]),
        GateType::ForeignMul1 => Some([F::zero(), F::one(), F::zero()]),
        GateType::ForeignMul2 => Some([F::zero(), F::zero(), F::one()]),
        _ => None,
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
        let mut alphas = Alphas::<F>::default();
        alphas.register(ArgumentType::Gate(self.typ), ForeignMul1::<F>::CONSTRAINTS);

        // Get constraints for this circuit gate
        let constraints = circuit_gate_combined_constraints(self.typ, &alphas);

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
            foreign_mul_selector: gate_type_to_selector::<F>(self.typ),
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

fn append_foreign_field_element_rows<F: PrimeField>(witness: &mut [Vec<F>; COLUMNS], fe: BigUint) {
    assert!(fe.bits() <= (MAX_LIMBS * LIMB_SIZE) as u64);
    let mut last_row_number = 0;

    for (row, chunk) in fe
        .to_bytes_le() // F::from_bytes() below is little-endian
        .chunks(LIMB_SIZE / 8 + (LIMB_SIZE % 8 != 0) as usize)
        .enumerate()
    {
        // Convert chunk to field element and store in column 0
        let mut limb_bytes = chunk.to_vec();
        limb_bytes.resize(32 /* F::size_in_bytes() */, 0);
        let limb_fe = F::from_bytes(&limb_bytes).expect("failed to deserialize limb field bytes");

        // Initialize the row based on the limb and public input shape
        init_foreign_mul_row(witness, row, limb_fe);
        last_row_number += 1;
    }

    // Initialize last row
    init_foreign_mul_row(witness, last_row_number, F::zero());
}

pub fn create_witness<F: PrimeField>(a: BigUint, b: BigUint) -> [Vec<F>; COLUMNS] {
    assert!(a.bits() <= (MAX_LIMBS * LIMB_SIZE) as u64);
    let mut witness: [Vec<F>; COLUMNS] = array_init(|_| vec![F::zero(); 8]);
    append_foreign_field_element_rows(&mut witness, a);
    append_foreign_field_element_rows(&mut witness, b);
    witness
}

//
// Constraints
//

thread_local! {
    static CACHE: std::cell::RefCell<Cache>  = RefCell::new(Cache::default());
}

fn _cache<F: FftField>(mut x: E<F>) -> E<F> {
    CACHE.with(|cache| x = cache.borrow_mut().cache(x.clone()));
    x
}

fn two<F: FftField>() -> E<F> {
    Expr::Constant(ConstantExpr::Literal(2u32.into()))
}

fn three<F: FftField>() -> E<F> {
    Expr::Constant(ConstantExpr::Literal(3u32.into()))
}

fn sublimb_plookup_constraint<F: FftField>(_sublimb: &E<F>) -> E<F> {
    // TODO: implement plookup constraint for 12-bit sublimb
    E::zero()
}

// Crumb constraint for 2-bit sublimb
fn sublimb_crumb_constraint<F: FftField>(sublimb: &E<F>) -> E<F> {
    // Assert sublimb \in [0,3] i.e. assert x*(x - 1)*(x - 2)*(x - 3) == 0
    sublimb.clone()
        * (sublimb.clone() - E::one())
        * (sublimb.clone() - two())
        * (sublimb.clone() - three())
}

pub fn get_circuit_gates() -> Vec<GateType> {
    vec![
        GateType::ForeignMul0,
        GateType::ForeignMul1,
        GateType::ForeignMul2,
    ]
}

pub fn circuit_gate_combined_constraints<F: FftField>(typ: GateType, alphas: &Alphas<F>) -> E<F> {
    match typ {
        GateType::ForeignMul0 => ForeignMul0::combined_constraints(alphas),
        GateType::ForeignMul1 => ForeignMul1::combined_constraints(alphas),
        GateType::ForeignMul2 => ForeignMul2::combined_constraints(alphas),
        _ => panic!("invalid gate type"),
    }
}

pub fn gate_combined_constraints<F: FftField>(alphas: &Alphas<F>) -> E<F> {
    ForeignMul0::combined_constraints(alphas)
        + ForeignMul1::combined_constraints(alphas)
        + ForeignMul2::combined_constraints(alphas)
}

#[derive(Default)]
pub struct ForeignMul0<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignMul0<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignMul0);
    const CONSTRAINTS: u32 = 13;

    // Constraints for ForeignMul0
    //   * Operates on Curr row
    //   * Range constrain all sublimbs except p4 and p5
    //   * Constrain that combining all sublimbs equals the limb stored in column 0
    fn constraints() -> Vec<E<F>> {
        let w = |i| E::cell(Column::Witness(i), Curr);

        // Row structure
        //  Column w(i) 0    1       ... 4       5    6    7     ... 14
        //        Curr  limb plookup ... plookup copy copy crumb ... crumb

        // 1) Apply range constraints on sublimbs

        // Create 4 12-bit plookup range constraints
        let mut constraints: Vec<E<F>> =
            (1..5).map(|i| sublimb_plookup_constraint(&w(i))).collect();

        // Create 8 2-bit chunk range constraints
        constraints.append(
            &mut (7..COLUMNS)
                .map(|i| sublimb_crumb_constraint(&w(i)))
                .collect::<Vec<E<F>>>(),
        );

        // 2) Constrain that the combined sublimbs equals the limb stored in w(0) where
        //    limb = lp0 lp1 lp2 lp3 lp4 lp5 lc0 lc1 lc2 lc3 lc4 lc5 lc6 lc7
        //    in big-endian byte order.
        //
        //     Columns
        //    R        0      1    2    3    4    5    6    7    8    9    10   11   12   13   14
        //    o  Curr  limb   lp0  lp1  lp2  lp3  lp4  lp5  lc0  lc1  lc2  lc3  lc4  lc5  lc6  lc7  <- LSB
        //    w               76   64   52   40   28   16   14   12   10    8    6    4    2    0
        //    s
        //
        // Check limb =  lp0*2^0 + lp1*2^{12}  + ... + p5*2^{60}   + lc0*2^{72}  + lc1*2^{74}  + ... + lc7*2^{86}
        //       w(0) = w(1)*2^0 + w(2)*2^{12} + ... + w(6)*2^{60} + w(7)*2^{72} + w(8)*2^{74} + ... + w(14)*2^{86}
        //            = \sum i \in [1,7] 2^{12*(i - 1)}*w(i) + \sum i \in [8,14] 2^{2*(i - 7) + 6*12}*w(i)
        let combined_sublimbs = (1..COLUMNS).fold(E::zero(), |acc, i| {
            match i {
                0 => {
                    // ignore
                    acc
                }
                1..=7 => {
                    // 12-bit chunk offset
                    acc + two().pow(12 * (i as u64 - 1)) * w(i)
                }
                8..=COLUMNS => {
                    // 2-bit chunk offset
                    acc + two().pow(2 * (i as u64 - 7) + 6 * 12) * w(i)
                }
                _ => {
                    panic!("Invalid column index {}", i)
                }
            }
        });

        // w(0) = combined_sublimbs
        constraints.push(combined_sublimbs - w(0));

        constraints
    }
}

#[derive(Default)]
pub struct ForeignMul1<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignMul1<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignMul1);
    const CONSTRAINTS: u32 = 25;

    // Constraints for ForeignMul1
    //   * Operates on Curr and Next row
    //   * Range constrain all sublimbs
    //   * Constrain that combining all sublimbs equals the limb stored in row Curr, column 0
    fn constraints() -> Vec<E<F>> {
        let w_curr = |i| E::cell(Column::Witness(i), Curr);
        let w_next = |i| E::cell(Column::Witness(i), Next);

        // Constraints structure
        //  Column      0    1       ... 4       5     ... 14
        //        Curr  limb plookup ... plookup crumb ... crumb
        //        Next                           crumb ... crumb

        // 1) Apply range constraints on sublimbs

        // Create 4 12-bit plookup range constraints
        let mut constraints: Vec<E<F>> = (1..5)
            .map(|i| sublimb_plookup_constraint(&w_curr(i)))
            .collect();

        // Create 10 2-bit chunk range constraints using Curr row
        constraints.append(
            &mut (5..COLUMNS)
                .map(|i| sublimb_crumb_constraint(&w_curr(i)))
                .collect::<Vec<E<F>>>(),
        );

        // Create 10 more 2-bit chunk range constraints using Next row
        constraints.append(
            &mut (5..COLUMNS)
                .map(|i| sublimb_crumb_constraint(&w_next(i)))
                .collect::<Vec<E<F>>>(),
        );

        // 2) Constrain that the combined sublimbs equals the limb l2 stored in w(0) where
        //    l2 = lp0 lp1 lp2 lp3 lc0 lc1 lc2 lc3 lc4 lc5 lc6 lc7 lc8 lc9 lc10 lc11 lc12 lc13 lc14 lc15 lc16 lc17 lc18 lc19
        //    in little-endian byte order.
        //
        //     Columns
        //    R        0    1   2   3   4   5    6    7    8    9    10   11   12   13   14
        //    o  Curr  l2   lp0 lp1 lp2 lp3 lc0  lc1  lc2  lc3  lc4  lc5  lc6  lc7  lc8  lc9
        //    w  Next                       lc10 lc11 lc12 lc13 lc14 lc15 lc16 lc17 lc18 lc19
        //    s
        //
        // Check   l2 = lp0*2^0          + lp1*2^{12}       + ... + lp3*2^{36}       + lc0*2^{48}     + lc1*2^{50}     + ... + lc19*2^{66}
        //       w(0) = w_curr(1)*2^0    + w_curr(2)*2^{12} + ... + w_curr(4)*2^{36} + w_curr(5)*2^48 + w_curr(6)*2^50 + ... + w_curr(14)*2^66
        //            + w_next(5)*2^{68} + w_next(6)*2^{70} + ... + w_next(14)*2^{86}
        // (1st part) = \sum i \in [1,5] 2^{12*(i - 1)}*w_curr(i) + \sum i \in [6,14] 2^{2*(i - 5) + 4*12}*w_curr(i)
        // (2nd part) + \sum i \in [5,14] 2^{2*(i - 5} + 68)*w_next(i)

        // 1st part (Curr row): \sum i \in [1,5] 2^{12*(i - 1)}*w_curr(i) + \sum i \in [6,14] 2^{2*(i - 5) + 4*12}*w_curr(i)
        let combined_sublimbs = (1..COLUMNS).fold(E::zero(), |acc, i| {
            match i as usize {
                0 => {
                    // ignore
                    acc
                }
                1..=4 => {
                    // 12-bit chunk
                    acc + two().pow(12 * (i as u64 - 1)) * w_curr(i)
                }
                5..=COLUMNS => {
                    // 2-bit chunk
                    acc + two().pow(2 * (i as u64 - 5) + 4 * 12) * w_curr(i)
                }
                _ => {
                    panic!("Invalid column index {}", i)
                }
            }
        });

        // 2nd part (Next row): \sum i \in [5,14] 2^{2*(i - 5) + 68}*w_next(i)
        let combined_sublimbs = (5..COLUMNS).fold(combined_sublimbs, |acc, i| {
            // 2-bit chunk
            acc + two().pow(2 * (i as u64 - 5) + 68) * w_next(i)
        });

        // w(0) = combined_sublimbs
        constraints.push(combined_sublimbs - w_curr(0));

        constraints
    }
}

#[derive(Default)]
pub struct ForeignMul2<F>(PhantomData<F>);

impl<F> Argument<F> for ForeignMul2<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::ForeignMul2);
    const CONSTRAINTS: u32 = 5;

    // Constraints for ForeignMul2
    //   * Operates on Curr row
    //   * Range constrain sublimbs stored in columns 1 through 4
    //   * The contents of these cells are the 4 12-bit sublimbs that
    //     could not be plookup'ed in rows Curr - 3 and Curr - 2
    //   * Copy constraints are present (elsewhere) to make sure
    //     these cells are equal to those
    fn constraints() -> Vec<E<F>> {
        let w = |i| E::cell(Column::Witness(i), Curr);

        // Row structure
        //  Column w(i) 0    1       ... 4       5     6     7     ... 14
        //         Curr limb plookup ... plookup crumb crumb crumb ... crumb

        // Apply range constraints on sublimbs (create 4 12-bit plookup range constraints)
        // crumbs were constrained by ForeignMul1 circuit gate
        let mut constraints: Vec<E<F>> =
            (1..5).map(|i| sublimb_plookup_constraint(&w(i))).collect();

        // Temporary dummy constraint to avoid zero polynomial edge case
        // and avoid check that verifier does that all commitments aren't identically zero
        constraints.push(E::<F>::cell(
            Column::Index(GateType::Poseidon),
            CurrOrNext::Curr,
        ));

        constraints
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        circuits::{
            constraints::ConstraintSystem, gate::CircuitGate, polynomial::COLUMNS,
            polynomials::foreign_mul::create_witness, wires::Wire,
        },
        proof::ProverProof,
        prover_index::testing::new_index_for_test,
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
            oracle::pasta::fp_kimchi::params(),
            o1_utils::packed_modulus::<PallasField>(o1_utils::get_modulus::<VestaField>()),
            0,
        )
        .unwrap()
    }

    fn create_test_prover_index(
        foreign_modulus: BigUint,
        public_size: usize,
    ) -> ProverIndex<mina_curves::pasta::vesta::Affine> {
        let wires = array_init(|i| Wire::new(i));
        let gates = CircuitGate::<PallasField>::create_foreign_mul(&wires);
        new_index_for_test(
            gates,
            o1_utils::packed_modulus::<PallasField>(foreign_modulus),
            public_size,
        )
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

        let witness: [Vec<PallasField>; 15] = create_witness(
            biguint_from_hex_le("1112223334445556667777888999aaabbbcccdddeeefff111222333444555611"),
            biguint_from_hex_le("1112223334445556667777888999aaabbbcccdddeeefff111222333444555611"),
        );

        // gates[0] is ForeignMul0
        assert_eq!(cs.gates[0].verify_foreign_mul(0, &witness, &cs), Ok(()));

        // gates[1] is ForeignMul0
        assert_eq!(cs.gates[1].verify_foreign_mul(1, &witness, &cs), Ok(()));

        let witness: [Vec<PallasField>; 15] = create_witness(
            biguint_from_hex_le("f59abe33f5d808f8df3e63984621b01e375585fea8dd4030f71a0d80ac06d423"),
            biguint_from_hex_le("f59abe33f5d808f8df3e63984621b01e375585fea8dd4030f71a0d80ac06d423"),
        );

        // gates[0] is ForeignMul0
        assert_eq!(cs.gates[0].verify_foreign_mul(0, &witness, &cs), Ok(()));

        // gates[1] is ForeignMul0
        assert_eq!(cs.gates[1].verify_foreign_mul(1, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_foreign_mul0_invalid_witness() {
        let cs = create_test_constraint_system();

        let mut witness: [Vec<PallasField>; 15] = create_witness(
            biguint_from_hex_le("bca91cf9df6cfd8bd225fd3f46ba2f3f33809d0ee2e7ad338448b4ece7b4f622"),
            biguint_from_hex_le("bca91cf9df6cfd8bd225fd3f46ba2f3f33809d0ee2e7ad338448b4ece7b4f622"),
        );

        // Invalidate witness
        witness[5][0] += PallasField::one();

        // gates[0] is ForeignMul0
        assert_eq!(
            cs.gates[0].verify_foreign_mul(0, &witness, &cs),
            Err(String::from("Invalid ForeignMul0 constraint"))
        );

        let mut witness: [Vec<PallasField>; 15] = create_witness(
            biguint_from_hex_le("301a091e9f74cd459a448c311ae47fe2f4311db61ae1cbd2afee0171e2b5ca22"),
            biguint_from_hex_le("301a091e9f74cd459a448c311ae47fe2f4311db61ae1cbd2afee0171e2b5ca22"),
        );

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

        let witness: [Vec<PallasField>; 15] = create_witness(
            biguint_from_hex_le("72de0b593fbd97e172ddfb1d7c1f7488948c622a7ff6bffa0279e35a7c148733"),
            biguint_from_hex_le("72de0b593fbd97e172ddfb1d7c1f7488948c622a7ff6bffa0279e35a7c148733"),
        );

        // gates[2] is ForeignMul1
        assert_eq!(cs.gates[2].verify_foreign_mul(2, &witness, &cs), Ok(()));

        let witness: [Vec<PallasField>; 15] = create_witness(
            biguint_from_hex_le("58372fb93039e7106c68488dceb6cab3ffb0e7c8594dcc3bc7160321fcf6960d"),
            biguint_from_hex_le("58372fb93039e7106c68488dceb6cab3ffb0e7c8594dcc3bc7160321fcf6960d"),
        );

        // gates[2] is ForeignMul1
        assert_eq!(cs.gates[2].verify_foreign_mul(2, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_foreign_mul1_invalid_witness() {
        let cs = create_test_constraint_system();

        let mut witness: [Vec<PallasField>; 15] = create_witness(
            biguint_from_hex_le("260efa1879427b08ca608d455d9f39954b5243dd52117e9ed5982f94acd3e22c"),
            biguint_from_hex_le("260efa1879427b08ca608d455d9f39954b5243dd52117e9ed5982f94acd3e22c"),
        );

        // Corrupt witness
        witness[0][2] = witness[7][2];

        // gates[2] is ForeignMul1
        assert_eq!(
            cs.gates[2].verify_foreign_mul(2, &witness, &cs),
            Err(String::from("Invalid ForeignMul1 constraint"))
        );

        let mut witness: [Vec<PallasField>; 15] = create_witness(
            biguint_from_hex_le("afd209d02c77546022ea860f9340e4289ecdd783e9c0012fd383dcd2940cd51b"),
            biguint_from_hex_le("afd209d02c77546022ea860f9340e4289ecdd783e9c0012fd383dcd2940cd51b"),
        );

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

        let _witness: [Vec<PallasField>; 15] = create_witness(
            biguint_from_hex_le("1aed1a6bc2ca84ee6edaedea4eb9b623392d24f64dfb0a8134ff16289bfc3c1f"),
            biguint_from_hex_le("1aed1a6bc2ca84ee6edaedea4eb9b623392d24f64dfb0a8134ff16289bfc3c1f"),
        );

        // gates[3] is ForeignMul2 (cannot validate until plookup is implemented)
        // assert_eq!(cs.gates[3].verify_foreign_mul(3, &witness, &cs), Ok(()));

        let _witness: [Vec<PallasField>; 15] = create_witness(
            biguint_from_hex_le("fd944d6dad12b5398bd2901b92439c6af31eca1766a1915bcd611df90830b508"),
            biguint_from_hex_le("fd944d6dad12b5398bd2901b92439c6af31eca1766a1915bcd611df90830b508"),
        );

        // gates[3] is ForeignMul2 (cannot validate until plookup is implemented)
        // assert_eq!(cs.gates[3].verify_foreign_mul(3, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_foreign_mul2_invalid_witness() {
        let _cs = create_test_constraint_system();

        let mut witness: [Vec<PallasField>; 15] = create_witness(
            biguint_from_hex_le("56acede83576c45ec8c11a85ac97e2393a9f88308b4b42d1b1506f2faaafc02b"),
            biguint_from_hex_le("56acede83576c45ec8c11a85ac97e2393a9f88308b4b42d1b1506f2faaafc02b"),
        );

        // Corrupt witness
        witness[12][2] = witness[2][2];

        // gates[3] is ForeignMul2 (cannot validate until plookup is implemented)
        // assert_eq!(cs.gates[3].verify_foreign_mul(3, &witness, &cs), Ok(()));

        let mut witness: [Vec<PallasField>; 15] = create_witness(
            biguint_from_hex_le("56acede83576c45ec8c11a85ac97e2393a9f88308b4b42d1b1506f2faaafc02b"),
            biguint_from_hex_le("56acede83576c45ec8c11a85ac97e2393a9f88308b4b42d1b1506f2faaafc02b"),
        );

        // Corrupt witness
        witness[6][2] = witness[3][2];

        // gates[3] is ForeignMul2 (cannot validate until plookup is implemented)
        // assert_eq!(cs.gates[3].verify_foreign_mul(3, &witness, &cs), Ok(()));
    }

    use crate::{prover_index::ProverIndex, verifier::verify};
    use commitment_dlog::commitment::CommitmentCurve;
    use groupmap::GroupMap;
    use mina_curves::pasta as pasta_curves;
    use oracle::{
        constants::PlonkSpongeConstantsKimchi,
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };

    type BaseSponge =
        DefaultFqSponge<pasta_curves::vesta::VestaParameters, PlonkSpongeConstantsKimchi>;
    type ScalarSponge = DefaultFrSponge<pasta_curves::Fp, PlonkSpongeConstantsKimchi>;

    #[test]
    fn verify_foreign_mul_proof1() {
        // Create prover index
        let prover_index = create_test_prover_index(o1_utils::get_modulus::<VestaField>(), 0);

        // Create witness
        let witness: [Vec<PallasField>; 15] = create_witness(
            biguint_from_hex_le("56acede83576c45ec8c11a85ac97e2393a9f88308b4b42d1b1506f2faaafc02b"),
            biguint_from_hex_le("56acede83576c45ec8c11a85ac97e2393a9f88308b4b42d1b1506f2faaafc02b"),
        );

        // Verify computed witness satisfies the circuit
        prover_index.cs.verify(&witness, &[]).unwrap();

        // Generate proof
        let group_map = <pasta_curves::vesta::Affine as CommitmentCurve>::Map::setup();
        let proof =
            ProverProof::create::<BaseSponge, ScalarSponge>(&group_map, witness, &prover_index)
                .expect("failed to generate proof");

        // Get the verifier index
        let verifier_index = prover_index.verifier_index();

        // Verify proof
        let res = verify::<pasta_curves::vesta::Affine, BaseSponge, ScalarSponge>(
            &group_map,
            &verifier_index,
            &proof,
        );

        assert!(!res.is_err());
    }
}
