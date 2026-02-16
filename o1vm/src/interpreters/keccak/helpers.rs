use crate::{
    interpreters::keccak::interpreter::Interpreter,
    lookups::{Lookup, LookupTableIDs::*},
};
use ark_ff::{One, Zero};
use std::fmt::Debug;

/// This trait contains helper functions for the lookups used in the Keccak circuit
/// using the zkVM lookup tables
pub trait LogupHelpers<F: One + Debug + Zero>
where
    Self: Interpreter<F>,
{
    /// Adds a lookup to the RangeCheck16 table
    fn lookup_rc16(&mut self, flag: Self::Variable, value: Self::Variable) {
        self.add_lookup(flag, Lookup::read_one(RangeCheck16Lookup, vec![value]));
    }

    /// Adds a lookup to the Reset table
    fn lookup_reset(
        &mut self,
        flag: Self::Variable,
        dense: Self::Variable,
        sparse: Self::Variable,
    ) {
        self.add_lookup(flag, Lookup::read_one(ResetLookup, vec![dense, sparse]));
    }

    /// Adds a lookup to the Shift table
    fn lookup_sparse(&mut self, flag: Self::Variable, value: Self::Variable) {
        self.add_lookup(flag, Lookup::read_one(SparseLookup, vec![value]));
    }

    /// Adds a lookup to the Byte table
    fn lookup_byte(&mut self, flag: Self::Variable, value: Self::Variable) {
        self.add_lookup(flag, Lookup::read_one(ByteLookup, vec![value]));
    }

    /// Adds a lookup to the Pad table
    fn lookup_pad(&mut self, flag: Self::Variable, value: Vec<Self::Variable>) {
        self.add_lookup(flag, Lookup::read_one(PadLookup, value));
    }

    /// Adds a lookup to the RoundConstants table
    fn lookup_round_constants(&mut self, flag: Self::Variable, value: Vec<Self::Variable>) {
        self.add_lookup(flag, Lookup::read_one(RoundConstantsLookup, value));
    }

    fn read_syscall(&mut self, flag: Self::Variable, value: Vec<Self::Variable>) {
        self.add_lookup(flag, Lookup::read_one(SyscallLookup, value));
    }

    fn write_syscall(&mut self, flag: Self::Variable, value: Vec<Self::Variable>) {
        self.add_lookup(flag, Lookup::write_one(SyscallLookup, value));
    }
}

/// This trait contains helper functions for boolean operations used in the Keccak circuit
pub trait BoolHelpers<F: One + Debug + Zero>
where
    Self: Interpreter<F>,
{
    /// Degree-2 variable encoding whether the input is a boolean value (0 = yes)
    fn is_boolean(x: Self::Variable) -> Self::Variable {
        x.clone() * (x - Self::Variable::one())
    }

    /// Degree-1 variable encoding the negation of the input
    /// Note: it only works as expected if the input is a boolean value
    fn not(x: Self::Variable) -> Self::Variable {
        Self::Variable::one() - x
    }

    /// Degree-1 variable encoding whether the input is the value one (0 = yes)
    fn is_one(x: Self::Variable) -> Self::Variable {
        Self::not(x)
    }

    /// Degree-2 variable encoding whether the first input is nonzero (0 = yes).
    /// It requires the second input to be the multiplicative inverse of the first.
    /// Note: if the first input is zero, there is no multiplicative inverse.
    fn is_nonzero(x: Self::Variable, x_inv: Self::Variable) -> Self::Variable {
        Self::is_one(x * x_inv)
    }

    // The following two degree-2 constraints define the is_zero function meaning (1 = yes):
    // - if x = 0 then is_zero(x) = 1
    // - if x ≠ 0 then is_zero(x) = 0
    // It is obtained by combining these two equations:
    // x * xinv = 1 - z
    // x * z = 0
    // When x = 0, xinv could be anything, like 1.
    fn is_zero(
        x: Self::Variable,
        x_inv: Self::Variable,
        z: Self::Variable,
    ) -> (Self::Variable, Self::Variable) {
        (
            x.clone() * x_inv.clone() - z.clone() + Self::Variable::one(),
            x * z,
        )
    }

    /// Degree-2 variable encoding the XOR of two variables which should be boolean (1 = true)
    fn xor(x: Self::Variable, y: Self::Variable) -> Self::Variable {
        x.clone() + y.clone() - Self::constant(2) * x * y
    }

    /// Degree-2 variable encoding the OR of two variables, which should be boolean (1 = true)
    fn or(x: Self::Variable, y: Self::Variable) -> Self::Variable {
        x.clone() + y.clone() - x * y
    }

    /// Degree-2 variable encoding whether at least one of the two inputs is zero (0 = yes)
    fn either_zero(x: Self::Variable, y: Self::Variable) -> Self::Variable {
        x * y
    }
}

/// This trait contains helper functions for arithmetic operations used in the Keccak circuit
pub trait ArithHelpers<F: One + Debug + Zero>
where
    Self: Interpreter<F>,
{
    /// Returns a variable representing the value zero
    fn zero() -> Self::Variable {
        Self::constant(0)
    }
    /// Returns a variable representing the value one
    fn one() -> Self::Variable {
        Self::constant(1)
    }
    /// Returns a variable representing the value two
    fn two() -> Self::Variable {
        Self::constant(2)
    }

    /// Returns a variable representing the value 2^x
    fn two_pow(x: u64) -> Self::Variable;
}
