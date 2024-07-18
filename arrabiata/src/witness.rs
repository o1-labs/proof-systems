use ark_ec::AffineCurve;
use ark_ff::PrimeField;
use ark_poly::Evaluations;
use kimchi::circuits::domains::EvaluationDomains;
use log::{debug, info};
use mina_poseidon::FqSponge;
use num_bigint::BigUint;
use o1_utils::field_helpers::FieldHelpers;
use poly_commitment::{commitment::CommitmentCurve, srs::SRS, PolyComm, SRS as _};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::time::Instant;

use crate::{columns::Column, interpreter::InterpreterEnv, NUMBER_OF_COLUMNS};

/// An environment that can be shared between IVC instances
/// It contains all the accumulators that can be picked for a given fold
/// instance k, including the sponges.
// FIXME: run the interpreter over integers and not field elements to avoid the
// reduction at every step?
pub struct Env<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: AffineCurve<ScalarField = Fp, BaseField = Fq>,
    E2: AffineCurve<ScalarField = Fq, BaseField = Fp>,
    E1Sponge: FqSponge<Fq, E1, Fp>,
    E2Sponge: FqSponge<Fp, E2, Fq>,
> {
    // ----------------
    // Setup related (domains + SRS)
    /// Domain for Fp
    pub domain_fp: EvaluationDomains<Fp>,

    /// Domain for Fq
    pub domain_fq: EvaluationDomains<Fq>,

    /// SRS for the first curve
    pub srs_e1: SRS<E1>,

    /// SRS for the second curve
    pub srs_e2: SRS<E2>,
    // ----------------

    // ----------------
    // Information related to the IVC, which will be used by the prover/verifier
    // at the end of the whole execution
    // FIXME
    pub ivc_accumulator_e1: E1,

    // FIXME
    pub ivc_accumulator_e2: E2,

    /// Commitments to the previous instances
    pub previous_commitments_e1: Vec<PolyComm<E1>>,
    pub previous_commitments_e2: Vec<PolyComm<E2>>,
    // ----------------

    // ----------------
    // Data only used by the interpreter while building the witness over time
    /// The index of the latest allocated variable in the circuit.
    /// It is used to allocate new variables without having to keep track of the
    /// position.
    pub idx_var: usize,

    /// Current processing row. Used to build the witness.
    pub current_row: usize,

    /// State of the current row in the execution trace
    pub state: [BigUint; NUMBER_OF_COLUMNS],

    /// The sponges will be used to simulate the verifier messages, and will
    /// also be used to verify the consistency of the computation by hashing the
    /// public IO.
    pub sponge_e1: E1Sponge,
    pub sponge_e2: E2Sponge,

    /// List of public inputs, used first to verify the consistency of the
    /// previous iteration.
    pub current_iteration: u64,

    /// A previous hash, encoded in 2 chunks of 128 bits.
    pub previous_hash: [u128; 2],
    // ----------------
    /// The witness of the current instance of the circuit.
    /// The size of the outer vector must be equal to the number of columns in the
    /// circuit.
    /// The size of the inner vector must be equal to the number of rows in
    /// the circuit.
    ///
    /// The layout columns/rows is used to avoid rebuilding the witness per
    /// column when committing to the witness.
    pub witness: Vec<Vec<BigUint>>,

    // --------------
    // Inputs
    /// Initial input
    pub z0: BigUint,

    /// Current input
    pub zi: BigUint,
    // ---------------

    // ---------------
    // Only used to have type safety and think about the design at the
    // type-level
    pub _marker: std::marker::PhantomData<(Fp, Fq, E1, E2)>,
    // ---------------
}

impl<
        Fp: PrimeField,
        Fq: PrimeField,
        E1: AffineCurve<ScalarField = Fp, BaseField = Fq>,
        E2: AffineCurve<ScalarField = Fq, BaseField = Fp>,
        E1Sponge: FqSponge<Fq, E1, Fp>,
        E2Sponge: FqSponge<Fp, E2, Fq>,
    > InterpreterEnv for Env<Fp, Fq, E1, E2, E1Sponge, E2Sponge>
{
    type Position = Column;

    /// For efficiency, and for having a single interpreter, we do not use one
    /// of the fields. We use a generic BigUint to represent the values.
    /// When building the witness, we will reduce into the corresponding field
    type Variable = BigUint;

    fn variable(&self, _column: Self::Position) -> Self::Variable {
        todo!();
    }

    fn allocate(&mut self) -> Self::Position {
        let pos = Column::X(self.idx_var);
        self.idx_var += 1;
        assert!(self.idx_var < NUMBER_OF_COLUMNS, "Maximum number of columns reached ({NUMBER_OF_COLUMNS}), increase the number of columns");
        pos
    }

    fn constant(&self, v: BigUint) -> Self::Variable {
        v
    }

    fn add_constraint(&mut self, _x: Self::Variable) {
        unimplemented!("Only when building the constraints")
    }

    fn assert_zero(&mut self, var: Self::Variable) {
        assert_eq!(var, BigUint::from(0_usize));
    }

    fn assert_equal(&mut self, x: Self::Variable, y: Self::Variable) {
        assert_eq!(x, y);
    }

    // FIXME: it should not be a check, but it should build the related logup
    // values
    fn range_check16(&mut self, x: Self::Position) {
        let Column::X(idx) = x;
        let x = self.state[idx].clone();
        assert!(x < BigUint::from(2_usize).pow(16));
    }

    fn square(&mut self, col: Self::Position, x: Self::Variable) -> Self::Variable {
        let Column::X(idx) = col;
        let res = x.clone() * x.clone();
        self.state[idx] = res.clone();
        res
    }

    /// Flagged as unsafe as it does require an additional range check
    unsafe fn bitmask_be(
        &mut self,
        x: &Self::Variable,
        highest_bit: u32,
        lowest_bit: u32,
        position: Self::Position,
    ) -> Self::Variable {
        let diff = highest_bit - lowest_bit;
        assert!(
            diff <= 16,
            "The difference between the highest and lowest bit should be less than 16"
        );
        let rht = BigUint::from(1_usize << diff) - BigUint::from(1_usize);
        let lft = x >> lowest_bit;
        let res: BigUint = lft & rht;
        let Column::X(idx) = position;
        self.state[idx] = res.clone();
        res
    }

    // FIXME: for now, we use the row number and compute the square.
    // This is only for testing purposes, and having something to build the
    // witness.
    fn fetch_input(&mut self, res: Self::Position) -> Self::Variable {
        let x = BigUint::from(self.current_row as u64);
        // Update the state accordinly to keep track of it
        let Column::X(idx) = res;
        self.state[idx] = x.clone();
        x
    }

    /// Reset the environment to build the next row
    fn reset(&mut self) {
        // Save the current state in the witness
        self.state.iter().enumerate().for_each(|(i, x)| {
            self.witness[i][self.current_row] = x.clone();
        });
        self.current_row += 1;
        self.idx_var = 0;
        // Rest the state for the next row
        self.state = std::array::from_fn(|_| BigUint::from(0_usize));
    }

    /// FIXME: check if we need to pick the left or right sponge
    fn coin_folding_combiner(&mut self, pos: Self::Position) -> Self::Variable {
        let r = if self.current_iteration % 2 == 0 {
            self.sponge_e1.challenge().to_biguint()
        } else {
            self.sponge_e2.challenge().to_biguint()
        };
        let Column::X(idx) = pos;
        self.state[idx] = r.clone();
        r
    }
}

impl<
        Fp: PrimeField,
        Fq: PrimeField,
        E1: CommitmentCurve<ScalarField = Fp, BaseField = Fq>,
        E2: CommitmentCurve<ScalarField = Fq, BaseField = Fp>,
        E1Sponge: FqSponge<Fq, E1, Fp>,
        E2Sponge: FqSponge<Fp, E2, Fq>,
    > Env<Fp, Fq, E1, E2, E1Sponge, E2Sponge>
{
    pub fn new(
        srs_log2_size: usize,
        z0: BigUint,
        sponge_e1: E1Sponge,
        sponge_e2: E2Sponge,
    ) -> Self {
        let srs_size = 1 << srs_log2_size;
        let domain_fp = EvaluationDomains::<Fp>::create(srs_size).unwrap();
        let domain_fq = EvaluationDomains::<Fq>::create(srs_size).unwrap();

        info!("Create an SRS of size {srs_log2_size} for the first curve");
        let srs_e1: SRS<E1> = {
            let start = Instant::now();
            let mut srs = SRS::create(srs_size);
            debug!("SRS for E1 created in {:?}", start.elapsed());
            let start = Instant::now();
            srs.add_lagrange_basis(domain_fp.d1);
            debug!("Lagrange basis for E1 added in {:?}", start.elapsed());
            srs
        };
        info!("Create an SRS of size {srs_log2_size} for the second curve");
        let srs_e2: SRS<E2> = {
            let start = Instant::now();
            let mut srs = SRS::create(srs_size);
            debug!("SRS for E2 created in {:?}", start.elapsed());
            let start = Instant::now();
            srs.add_lagrange_basis(domain_fq.d1);
            debug!("Lagrange basis for E2 added in {:?}", start.elapsed());
            srs
        };

        let mut witness: Vec<Vec<BigUint>> = Vec::with_capacity(NUMBER_OF_COLUMNS);
        {
            let mut vec: Vec<BigUint> = Vec::with_capacity(srs_size);
            (0..srs_size).for_each(|_| vec.push(BigUint::from(0_usize)));
            (0..NUMBER_OF_COLUMNS).for_each(|_| witness.push(vec.clone()));
        };
        // Default set to the blinders
        let previous_commitments_e1: Vec<PolyComm<E1>> = (0..NUMBER_OF_COLUMNS)
            .map(|_| PolyComm::new(vec![srs_e1.h]))
            .collect();
        let previous_commitments_e2: Vec<PolyComm<E2>> = (0..NUMBER_OF_COLUMNS)
            .map(|_| PolyComm::new(vec![srs_e2.h]))
            .collect();
        Self {
            // -------
            // Setup
            domain_fp,
            domain_fq,
            srs_e1,
            srs_e2,
            // -------
            // -------
            // IVC only
            ivc_accumulator_e1: E1::zero(),
            ivc_accumulator_e2: E2::zero(),
            previous_commitments_e1,
            previous_commitments_e2,
            // ------
            // ------
            idx_var: 0,
            current_row: 0,
            state: std::array::from_fn(|_| BigUint::from(0_usize)),
            sponge_e1,
            sponge_e2,
            current_iteration: 0,
            previous_hash: [0; 2],
            // ------
            // ------
            // Used by the interpreter
            // Used to allocate variables
            // Witness builder related
            witness,
            // ------
            // Inputs
            z0: z0.clone(),
            zi: z0,
            // ------
            _marker: std::marker::PhantomData,
        }
    }

    /// Reset the environment to build the next iteration
    pub fn reset_for_next_iteration(&mut self) {
        // Rest the state for the next row
        self.current_row = 0;
        self.state = std::array::from_fn(|_| BigUint::from(0_usize));
        self.idx_var = 0;
    }

    /// The blinder used to commit, to avoid committing to the zero polynomial
    /// and accumulate it in the IVC.
    ///
    /// It is part of the instance, and it is accumulated in the IVC.
    pub fn accumulate_commitment_blinder(&mut self) {
        // TODO
    }

    /// Compute the commitments to the current witness, and update the previous
    /// instances.
    // Might be worth renaming this function
    pub fn compute_and_update_previous_commitments(&mut self) {
        if self.current_iteration % 2 == 0 {
            let comms: Vec<PolyComm<E1>> = self
                .witness
                .par_iter()
                .map(|evals| {
                    let evals: Vec<Fp> = evals
                        .par_iter()
                        .map(|x| Fp::from_biguint(x).unwrap())
                        .collect();
                    let evals = Evaluations::from_vec_and_domain(evals.to_vec(), self.domain_fp.d1);
                    self.srs_e1
                        .commit_evaluations_non_hiding(self.domain_fp.d1, &evals)
                })
                .collect();
            self.previous_commitments_e1 = comms
        } else {
            let comms: Vec<PolyComm<E2>> = self
                .witness
                .iter()
                .map(|evals| {
                    let evals: Vec<Fq> = evals
                        .par_iter()
                        .map(|x| Fq::from_biguint(x).unwrap())
                        .collect();
                    let evals = Evaluations::from_vec_and_domain(evals.to_vec(), self.domain_fq.d1);
                    self.srs_e2
                        .commit_evaluations_non_hiding(self.domain_fq.d1, &evals)
                })
                .collect();
            self.previous_commitments_e2 = comms
        }
    }

    /// Compute the output of the application on the previous output
    // TODO: we should compute the hash of the previous commitments, only on
    // CPU?
    pub fn compute_output(&mut self) {
        self.zi = BigUint::from(42_usize)
    }
}
