use ark_ec::AffineCurve;
use ark_ff::PrimeField;
use log::debug;
use mina_poseidon::{constants::SpongeConstants, poseidon::ArithmeticSponge};
use poly_commitment::{commitment::CommitmentCurve, srs::SRS};

use crate::{columns::Column, interpreter::InterpreterEnv, NUMBER_OF_COLUMNS};

/// An environment that can be shared between IVC instances
/// It contains all the accumulators that can be picked for a given fold
/// instance k, including the sponges.
pub struct Env<
    Fp: PrimeField,
    Fq: PrimeField,
    SpongeConfig: SpongeConstants,
    E1: AffineCurve<ScalarField = Fp, BaseField = Fq>,
    E2: AffineCurve<ScalarField = Fq, BaseField = Fp>,
> {
    /// SRS for the first curve
    pub srs_e1: SRS<E1>,

    /// SRS for the second curve
    pub srs_e2: SRS<E2>,

    /// The index of the latest allocated variable in the circuit.
    /// It is used to allocate new variables without having to keep track of the
    /// position.
    pub idx_var: usize,

    /// Current processing row. Used to build the witness.
    pub current_row: usize,

    /// State of the current row in the execution trace
    pub state: [Fp; NUMBER_OF_COLUMNS],

    // FIXME
    pub ivc_accumulator_e1: E1,

    // FIXME
    pub ivc_accumulator_e2: E2,

    // FIXME: must not be an option
    pub sponge_fp: Option<ArithmeticSponge<Fp, SpongeConfig>>,

    /// List of public inputs, used first to verify the consistency of the
    /// previous iteration.
    pub current_iteration: u64,

    /// A previous hash, encoded in 2 chunks of 128 bits.
    pub previous_hash: [u128; 2],

    /// The witness of the current instance of the circuit.
    /// The size of the outer vector must be equal to the number of rows in the
    /// circuit.
    /// The size of the inner vector must be equal to the number of columns in
    /// the circuit.
    pub witness: Vec<Vec<Fp>>,
}

impl<
        Fp: PrimeField,
        Fq: PrimeField,
        SpongeConfig: SpongeConstants,
        E1: AffineCurve<ScalarField = Fp, BaseField = Fq>,
        E2: AffineCurve<ScalarField = Fq, BaseField = Fp>,
    > InterpreterEnv for Env<Fp, Fq, SpongeConfig, E1, E2>
{
    type Position = Column;

    // FIXME
    type Variable = Fp;

    fn variable(&self, _column: Self::Position) -> Self::Variable {
        todo!();
    }

    fn allocate(&mut self) -> Self::Position {
        let pos = Column::X(self.idx_var);
        self.idx_var += 1;
        pos
    }

    fn add_constraint(&mut self, _x: Self::Variable) {
        unimplemented!("Only when building the constraints")
    }

    fn assert_zero(&mut self, var: Self::Variable) {
        assert_eq!(var, Fp::zero());
    }

    fn assert_equal(&mut self, x: Self::Variable, y: Self::Variable) {
        assert_eq!(x, y);
    }

    fn square(&mut self, col: Self::Position, x: Self::Variable) -> Self::Variable {
        let Column::X(idx) = col;
        let res = x * x;
        self.state[idx] = res;
        res
    }

    // FIXME: for now, we use the row number and compute the square.
    // This is only for testing purposes, and having something to build the
    // witness.
    fn fetch_input(&mut self, res: Self::Position) -> Self::Variable {
        let x = Fp::from(self.current_row as u64);
        // Update the state accordinly to keep track of it
        let Column::X(idx) = res;
        self.state[idx] = x;
        x
    }

    /// Reset the environment to build the next row
    fn reset(&mut self) {
        self.current_row += 1;
        self.idx_var = 0;
        // Save the current state in the witness
        self.witness.push(self.state.to_vec());
        // Rest the state for the next row
        self.state = [Fp::zero(); NUMBER_OF_COLUMNS];
    }

    fn reset_for_next_iteration(&mut self) {
        // Rest the state for the next row
        self.current_row = 0;
        self.state = [Fp::zero(); NUMBER_OF_COLUMNS];
        self.idx_var = 0;
    }
}

impl<
        Fp: PrimeField,
        Fq: PrimeField,
        SpongeConfig: SpongeConstants,
        E1: CommitmentCurve<ScalarField = Fp, BaseField = Fq>,
        E2: CommitmentCurve<ScalarField = Fq, BaseField = Fp>,
    > Env<Fp, Fq, SpongeConfig, E1, E2>
{
    pub fn new(srs_log2_size: usize) -> Self {
        debug!("Create an SRS of size {srs_log2_size} for the first curve");
        let srs_e1: SRS<E1> = SRS::create(1 << srs_log2_size);
        debug!("Create an SRS of size {srs_log2_size} for the second curve");
        let srs_e2: SRS<E2> = SRS::create(1 << srs_log2_size);
        Self {
            srs_e1,
            srs_e2,
            ivc_accumulator_e1: E1::zero(),
            ivc_accumulator_e2: E2::zero(),
            sponge_fp: None,
            current_iteration: 0,
            previous_hash: [0; 2],
            // Used to allocate variables
            idx_var: 0,
            // Witness builder related
            witness: Vec::new(),
            current_row: 0,
            state: [Fp::zero(); NUMBER_OF_COLUMNS],
        }
    }
}

impl<
        Fp: PrimeField,
        Fq: PrimeField,
        SpongeConfig: SpongeConstants,
        E1: CommitmentCurve<ScalarField = Fp, BaseField = Fq>,
        E2: CommitmentCurve<ScalarField = Fq, BaseField = Fp>,
    > Default for Env<Fp, Fq, SpongeConfig, E1, E2>
{
    /// By default, we will suppose we have 2^16 rows.
    fn default() -> Self {
        Self::new(16)
    }
}
