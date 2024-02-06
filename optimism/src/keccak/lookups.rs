//! This module includes the lookups of the Keccak circuit
use crate::{
    keccak::{
        column::KeccakColumn,
        environment::{KeccakEnv, KeccakEnvironment},
        ArithOps, BoolOps, E,
    },
    lookup::{Lookup, LookupTables, Lookups, TWO_TO_16_UPPERBOUND},
    DOMAIN_SIZE,
};
use ark_ff::Field;
use kimchi::circuits::polynomials::keccak::constants::{
    DIM, QUARTERS, RATE_IN_BYTES, ROUNDS, SHIFTS, SHIFTS_LEN, STATE_LEN,
};

/// When tables have more entries than circuit rows,
/// they are split into multiple tables (7 of size 2^15)
// FIXME: This does not account for syscalls nor step ram lookups
pub(crate) const NUM_KECCAK_SUBTABLES: u32 =
    (TWO_TO_16_UPPERBOUND * 3 + (ROUNDS as u32) + (RATE_IN_BYTES as u32) + 1 << 8)
        / (DOMAIN_SIZE as u32)
        + 1;

/// The number of lookups per row in the Keccak circuit
// FIXME: This does not account for syscalls nor step ram lookups
pub(crate) const NUM_KECCAK_LOOKUPS_PER_ROW: u64 = 2342;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeccakLookupColumns<T> {
    /// Multiplicities of each table entry.
    #[allow(dead_code)]
    pub multiplicities: [T; NUM_KECCAK_SUBTABLES as usize],
    /// Each table entry.
    #[allow(dead_code)]
    pub table_entries: [T; NUM_KECCAK_SUBTABLES as usize],
    /// All lookup requests per row.
    #[allow(dead_code)]
    pub lookup_requests: [T; NUM_KECCAK_LOOKUPS_PER_ROW as usize],
    /// Selectors of each lookup per row.
    #[allow(dead_code)]
    pub selectors: [T; NUM_KECCAK_LOOKUPS_PER_ROW as usize],
}

impl<Fp: Field> Lookups for KeccakEnv<Fp> {
    type Column = KeccakColumn;
    type Variable = E<Fp>;

    fn add_lookup(&mut self, lookup: Lookup<Self::Variable>) {
        self.lookups.push(lookup);
    }

    /// Adds all 2481 lookups to the Keccak environment:
    /// - 2342 lookups for the step row
    /// - 2 lookups for the inter-step channel
    /// - 136 lookups for the syscall channel (preimage bytes)
    /// - 1 lookups for the syscall channel (hash)
    fn lookups(&mut self) {
        // SPONGE LOOKUPS
        self.lookups_sponge();

        // ROUND LOOKUPS
        {
            // THETA LOOKUPS
            self.lookups_round_theta();
            // PIRHO LOOKUPS
            self.lookups_round_pirho();
            // CHI LOOKUPS
            self.lookups_round_chi();
            // IOTA LOOKUPS
            self.lookups_round_iota();
        }

        // INTER-STEP CHANNEL
        // Write outputs for next step if not a squeeze and read inputs of curr step if not a root
        self.lookup_steps();

        // COMMUNICATION CHANNEL: read bytes of current block
        self.lookup_syscall_preimage();

        // COMMUNICATION CHANNEL: Write hash output
        self.lookup_syscall_hash();
    }
}

/// This trait adds useful methods to deal with lookups in the Keccak environment
pub(crate) trait KeccakLookups {
    type Column;
    type Variable: std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + Clone;

    /// Reads Lookups containing the 136 bytes of the block of the preimage
    fn lookup_syscall_preimage(&mut self);

    /// Writes a Lookup containing the 31byte output of the hash (excludes the MSB)
    fn lookup_syscall_hash(&mut self);

    /// Reads a Lookup containing the input of a step
    /// and writes a Lookup containing the output of the next step
    fn lookup_steps(&mut self);

    /// Adds a lookup to the RangeCheck16 table
    fn lookup_rc16(&mut self, flag: Self::Variable, value: Self::Variable);

    /// Adds a lookup to the Reset table
    fn lookup_reset(&mut self, flag: Self::Variable, dense: Self::Variable, sparse: Self::Variable);

    /// Adds a lookup to the Shift table
    fn lookup_sparse(&mut self, flag: Self::Variable, value: Self::Variable);

    /// Adds a lookup to the Byte table
    fn lookup_byte(&mut self, flag: Self::Variable, value: Self::Variable);

    /// Adds the 601 lookups required for the sponge
    fn lookups_sponge(&mut self);

    /// Adds the 140 lookups required for Theta in the round
    fn lookups_round_theta(&mut self);

    /// Adds the 800 lookups required for PiRho in the round
    fn lookups_round_pirho(&mut self);

    /// Adds the 800 lookups required for Chi in the round
    fn lookups_round_chi(&mut self);

    /// Adds the 1 lookup required for Iota in the round
    fn lookups_round_iota(&mut self);
}

impl<Fp: Field> KeccakLookups for KeccakEnv<Fp> {
    type Column = KeccakColumn;
    type Variable = E<Fp>;

    // TODO: optimize this by using a single lookup reusing PadSuffix
    fn lookup_syscall_preimage(&mut self) {
        for i in 0..RATE_IN_BYTES {
            self.add_lookup(Lookup::read_if(
                self.is_absorb(),
                LookupTables::SyscallLookup,
                vec![
                    self.hash_index(),
                    Self::constant(self.block_idx * RATE_IN_BYTES as u64 + i as u64),
                    self.sponge_byte(i),
                ],
            ));
        }
    }

    fn lookup_syscall_hash(&mut self) {
        let bytes31 = (1..32).fold(Self::zero(), |acc, i| {
            acc * Self::two_pow(8) + self.sponge_byte(i)
        });
        self.add_lookup(Lookup::write_if(
            self.is_squeeze(),
            LookupTables::SyscallLookup,
            vec![self.hash_index(), bytes31],
        ));
    }

    fn lookup_steps(&mut self) {
        // (if not a root) Output of previous step is input of current step
        self.add_lookup(Lookup::read_if(
            Self::not(self.is_root()),
            LookupTables::KeccakStepLookup,
            self.input_of_step(),
        ));
        // (if not a squeeze) Input for next step is output of current step
        self.add_lookup(Lookup::write_if(
            Self::not(self.is_squeeze()),
            LookupTables::KeccakStepLookup,
            self.output_of_step(),
        ));
    }

    fn lookup_rc16(&mut self, flag: Self::Variable, value: Self::Variable) {
        self.add_lookup(Lookup::read_if(
            flag,
            LookupTables::RangeCheck16Lookup,
            vec![value],
        ));
    }

    fn lookup_reset(
        &mut self,
        flag: Self::Variable,
        dense: Self::Variable,
        sparse: Self::Variable,
    ) {
        self.add_lookup(Lookup::read_if(
            flag,
            LookupTables::ResetLookup,
            vec![dense, sparse],
        ));
    }

    fn lookup_sparse(&mut self, flag: Self::Variable, value: Self::Variable) {
        self.add_lookup(Lookup::read_if(
            flag,
            LookupTables::SparseLookup,
            vec![value],
        ));
    }

    fn lookup_byte(&mut self, flag: Self::Variable, value: Self::Variable) {
        self.add_lookup(Lookup::read_if(flag, LookupTables::ByteLookup, vec![value]));
    }

    fn lookups_sponge(&mut self) {
        // PADDING LOOKUPS
        // Power of two corresponds to 2^pad_length
        // Pad suffixes correspond to 10*1 rule
        self.add_lookup(Lookup::read_if(
            self.is_pad(),
            LookupTables::PadLookup,
            vec![
                self.pad_length(),
                self.two_to_pad(),
                self.pad_suffix(0),
                self.pad_suffix(1),
                self.pad_suffix(2),
                self.pad_suffix(3),
                self.pad_suffix(4),
            ],
        ));
        // BYTES LOOKUPS
        for i in 0..200 {
            // Bytes are <2^8
            self.lookup_byte(self.is_sponge(), self.sponge_byte(i));
        }
        // SHIFTS LOOKUPS
        for i in 100..SHIFTS_LEN {
            // Shifts1, Shifts2, Shifts3 are in the Sparse table
            self.lookup_sparse(self.is_sponge(), self.sponge_shifts(i));
        }
        for i in 0..STATE_LEN {
            // Shifts0 together with Bits composition by pairs are in the Reset table
            let dense = self.sponge_byte(2 * i) + self.sponge_byte(2 * i + 1) * Self::two_pow(8);
            self.lookup_reset(self.is_sponge(), dense, self.sponge_shifts(i));
        }
    }

    fn lookups_round_theta(&mut self) {
        for q in 0..QUARTERS {
            for x in 0..DIM {
                // Check that ThetaRemainderC < 2^64
                self.lookup_rc16(self.is_round(), self.remainder_c(x, q));
                // Check ThetaExpandRotC is the expansion of ThetaDenseRotC
                self.lookup_reset(
                    self.is_round(),
                    self.dense_rot_c(x, q),
                    self.expand_rot_c(x, q),
                );
                // Check ThetaShiftC0 is the expansion of ThetaDenseC
                self.lookup_reset(self.is_round(), self.dense_c(x, q), self.shifts_c(0, x, q));
                // Check that the rest of ThetaShiftsC are in the Sparse table
                for i in 1..SHIFTS {
                    self.lookup_sparse(self.is_round(), self.shifts_c(i, x, q));
                }
            }
        }
    }

    fn lookups_round_pirho(&mut self) {
        for q in 0..QUARTERS {
            for x in 0..DIM {
                for y in 0..DIM {
                    // Check that PiRhoRemainderE < 2^64 and PiRhoQuotientE < 2^64
                    self.lookup_rc16(self.is_round(), self.remainder_e(y, x, q));
                    self.lookup_rc16(self.is_round(), self.quotient_e(y, x, q));
                    // Check PiRhoExpandRotE is the expansion of PiRhoDenseRotE
                    self.lookup_reset(
                        self.is_round(),
                        self.dense_rot_e(y, x, q),
                        self.expand_rot_e(y, x, q),
                    );
                    // Check PiRhoShift0E is the expansion of PiRhoDenseE
                    self.lookup_reset(
                        self.is_round(),
                        self.dense_e(y, x, q),
                        self.shifts_e(0, y, x, q),
                    );
                    // Check that the rest of PiRhoShiftsE are in the Sparse table
                    for i in 1..SHIFTS {
                        self.lookup_sparse(self.is_round(), self.shifts_e(i, y, x, q));
                    }
                }
            }
        }
    }

    fn lookups_round_chi(&mut self) {
        for i in 0..SHIFTS_LEN {
            // Check ChiShiftsB and ChiShiftsSum are in the Sparse table
            self.lookup_sparse(self.is_round(), self.vec_shifts_b()[i].clone());
            self.lookup_sparse(self.is_round(), self.vec_shifts_sum()[i].clone());
        }
    }

    fn lookups_round_iota(&mut self) {
        // Check round constants correspond with the current round
        self.add_lookup(Lookup::read_if(
            self.is_round(),
            LookupTables::RoundConstantsLookup,
            vec![
                self.round(),
                self.round_constants()[3].clone(),
                self.round_constants()[2].clone(),
                self.round_constants()[1].clone(),
                self.round_constants()[0].clone(),
            ],
        ));
    }
}
