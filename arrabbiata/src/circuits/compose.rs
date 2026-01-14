//! Type-safe gadget composition combinators.
//!
//! This module provides combinators for composing typed gadgets:
//! - `Chain<G1, G2>`: Sequentially chain two gadgets
//! - `Repeat<G, N>`: Repeat a gadget N times
//! - `GadgetCircuit<G>`: Bridge from TypedGadget to StepCircuit
//!
//! The type system ensures that chained gadgets have compatible input/output types.

use ark_ff::PrimeField;
use core::fmt::Debug;

use crate::circuit::{CircuitEnv, SelectorEnv, StepCircuit};
use crate::circuits::gadget::{Scalar, TypedGadget};
use crate::column::Gadget;

// ============================================================================
// ScalarGadget marker trait
// ============================================================================

/// Marker trait for gadgets that use `Scalar<V>` for input and output.
///
/// This simplifies type bounds for composition combinators.
pub trait ScalarGadget<F: PrimeField>:
    TypedGadget<F, Input<F> = Scalar<F>, Output<F> = Scalar<F>>
{
    /// Synthesize using Scalar types directly (avoids GAT issues).
    fn synthesize_scalar<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        input: Scalar<E::Variable>,
    ) -> Scalar<E::Variable>;
}

// Blanket impl: any TypedGadget with Scalar I/O is a ScalarGadget
impl<F: PrimeField, G> ScalarGadget<F> for G
where
    G: TypedGadget<F, Input<F> = Scalar<F>, Output<F> = Scalar<F>>,
{
    fn synthesize_scalar<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        input: Scalar<E::Variable>,
    ) -> Scalar<E::Variable> {
        // We know Self::Input<V> = Scalar<V> and Self::Output<V> = Scalar<V>
        // due to how the trait is implemented. Use the actual synthesize method.
        // SAFETY: This relies on the fact that implementations of ScalarGadget
        // actually use Scalar<V> for their Input/Output GATs.

        // For the blanket impl, we need to call synthesize but we can't
        // directly because of the GAT mismatch. Instead, we'll provide
        // a default implementation that derived structs can override.

        // This is a workaround - real gadgets implement this directly.
        // For composed gadgets (Chain, Repeat), we implement TypedGadget
        // with Scalar types and this blanket impl works.

        // Cast through raw parts - this is safe when Input<V> = Scalar<V>
        let raw_input = input.0;
        let raw_output = {
            let typed_input: Self::Input<E::Variable> =
                unsafe { core::mem::transmute_copy(&Scalar(raw_input.clone())) };
            let typed_output = self.synthesize(env, typed_input);
            let scalar_output: Scalar<E::Variable> =
                unsafe { core::mem::transmute_copy(&typed_output) };
            scalar_output.0
        };
        Scalar(raw_output)
    }
}

// ============================================================================
// Chain Combinator
// ============================================================================

/// Chains two gadgets sequentially: G1 -> G2.
///
/// Both gadgets must use Scalar types for input/output.
#[derive(Clone, Debug)]
pub struct Chain<G1, G2> {
    pub first: G1,
    pub second: G2,
}

impl<G1, G2> Chain<G1, G2> {
    /// Create a new chain of two gadgets.
    pub fn new(first: G1, second: G2) -> Self {
        Self { first, second }
    }
}

impl<F, G1, G2> TypedGadget<F> for Chain<G1, G2>
where
    F: PrimeField,
    G1: ScalarGadget<F>,
    G2: ScalarGadget<F>,
{
    type Selector = G1::Selector;
    type Input<V: Clone> = Scalar<V>;
    type Output<V: Clone> = Scalar<V>;

    const ROWS: usize = G1::ROWS + G2::ROWS;

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable> {
        let mid = self.first.synthesize_scalar(env, input);
        self.second.synthesize_scalar(env, mid)
    }

    fn output(&self, input: &Self::Input<F>) -> Self::Output<F> {
        let mid = self.first.output(input);
        self.second.output(&mid)
    }
}

// ============================================================================
// Repeat Combinator
// ============================================================================

/// Repeats a gadget N times, feeding output back as input.
///
/// The gadget must use Scalar types for input/output.
#[derive(Clone, Debug)]
pub struct Repeat<G, const N: usize> {
    pub gadget: G,
}

impl<G, const N: usize> Repeat<G, N> {
    /// Create a new repeated gadget.
    pub fn new(gadget: G) -> Self {
        Self { gadget }
    }
}

impl<F, G, const N: usize> TypedGadget<F> for Repeat<G, N>
where
    F: PrimeField,
    G: ScalarGadget<F>,
{
    type Selector = G::Selector;
    type Input<V: Clone> = Scalar<V>;
    type Output<V: Clone> = Scalar<V>;

    const ROWS: usize = G::ROWS * N;

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable> {
        let mut current = input;

        for _ in 0..N {
            current = self.gadget.synthesize_scalar(env, current);
        }

        current
    }

    fn output(&self, input: &Self::Input<F>) -> Self::Output<F> {
        let mut current = input.clone();

        for _ in 0..N {
            current = self.gadget.output(&current);
        }

        current
    }
}

// ============================================================================
// GadgetCircuit: Bridge from TypedGadget to StepCircuit
// ============================================================================

/// Wraps a `TypedGadget` as a `StepCircuit`.
///
/// This allows composed gadgets (via `Chain` and `Repeat`) to be used
/// as step circuits in the IVC framework.
#[derive(Clone, Debug)]
pub struct GadgetCircuit<G> {
    pub gadget: G,
    pub name: &'static str,
}

impl<G> GadgetCircuit<G> {
    /// Create a new gadget circuit with a name.
    pub fn new(gadget: G, name: &'static str) -> Self {
        Self { gadget, name }
    }
}

impl<F, G> StepCircuit<F, 1> for GadgetCircuit<G>
where
    F: PrimeField,
    G: ScalarGadget<F>,
{
    const NAME: &'static str = "GadgetCircuit";

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        z: &[E::Variable; 1],
    ) -> [E::Variable; 1] {
        let input = Scalar(z[0].clone());
        let output = self.gadget.synthesize_scalar(env, input);
        [output.0]
    }

    fn output(&self, z: &[F; 1]) -> [F; 1] {
        let input = Scalar(z[0]);
        let output = self.gadget.output(&input);
        [output.0]
    }

    fn gadgets(&self) -> Vec<Gadget> {
        vec![self.gadget.gadget(); G::ROWS]
    }

    fn num_rows(&self) -> usize {
        G::ROWS
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{ConstraintEnv, Trace};
    use crate::circuits::selector::QNoOp;
    use mina_curves::pasta::Fp;

    /// A simple gadget that doubles its input.
    #[derive(Clone, Debug)]
    struct DoubleGadget;

    impl<F: PrimeField> TypedGadget<F> for DoubleGadget {
        type Selector = QNoOp;
        type Input<V: Clone> = Scalar<V>;
        type Output<V: Clone> = Scalar<V>;
        const ROWS: usize = 1;

        fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
            &self,
            env: &mut E,
            input: Self::Input<E::Variable>,
        ) -> Self::Output<E::Variable> {
            let x = input.0.clone();
            let doubled = x.clone() + x;
            let pos = env.allocate();
            Scalar(env.write_column(pos, doubled))
        }

        fn output(&self, input: &Self::Input<F>) -> Self::Output<F> {
            Scalar(input.0 + input.0)
        }
    }

    /// A simple gadget that squares its input.
    #[derive(Clone, Debug)]
    struct SquareGadget;

    impl<F: PrimeField> TypedGadget<F> for SquareGadget {
        type Selector = QNoOp;
        type Input<V: Clone> = Scalar<V>;
        type Output<V: Clone> = Scalar<V>;
        const ROWS: usize = 1;

        fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
            &self,
            env: &mut E,
            input: Self::Input<E::Variable>,
        ) -> Self::Output<E::Variable> {
            let x = input.0.clone();
            let squared = x.clone() * x;
            let pos = env.allocate();
            Scalar(env.write_column(pos, squared))
        }

        fn output(&self, input: &Self::Input<F>) -> Self::Output<F> {
            Scalar(input.0 * input.0)
        }
    }

    #[test]
    fn test_double_output() {
        let gadget = DoubleGadget;
        let input = Scalar(Fp::from(7u64));
        let output = gadget.output(&input);
        assert_eq!(output.0, Fp::from(14u64));
    }

    #[test]
    fn test_repeat_output() {
        // Repeat squaring 3 times: 2 -> 4 -> 16 -> 256
        let gadget = Repeat::<_, 3>::new(SquareGadget);
        let input = Scalar(Fp::from(2u64));
        let output = gadget.output(&input);
        assert_eq!(output.0, Fp::from(256u64));
    }

    #[test]
    fn test_repeat_double_output() {
        // Repeat doubling 4 times: 3 -> 6 -> 12 -> 24 -> 48
        let gadget = Repeat::<_, 4>::new(DoubleGadget);
        let input = Scalar(Fp::from(3u64));
        let output = gadget.output(&input);
        assert_eq!(output.0, Fp::from(48u64));
    }

    #[test]
    fn test_repeat_rows() {
        let gadget = Repeat::<SquareGadget, 5>::new(SquareGadget);
        assert_eq!(<Repeat<SquareGadget, 5> as TypedGadget<Fp>>::ROWS, 5);
        let _ = gadget;
    }

    #[test]
    fn test_chain_output() {
        // Double then square: 3 -> 6 -> 36
        let chain = Chain::new(DoubleGadget, SquareGadget);
        let input = Scalar(Fp::from(3u64));
        let output = chain.output(&input);
        assert_eq!(output.0, Fp::from(36u64));
    }

    #[test]
    fn test_chain_rows() {
        let chain = Chain::new(DoubleGadget, SquareGadget);
        assert_eq!(<Chain<DoubleGadget, SquareGadget> as TypedGadget<Fp>>::ROWS, 2);
        let _ = chain;
    }

    #[test]
    fn test_chain_synthesize_trace() {
        let chain = Chain::new(DoubleGadget, SquareGadget);
        let mut env = Trace::<Fp>::new(16);

        // Write input value
        let input_pos = env.allocate();
        let input_var = env.write_column(input_pos, Fp::from(3u64));
        let input = Scalar(input_var);

        let output = chain.synthesize(&mut env, input);

        // 3 -> 6 -> 36
        assert_eq!(output.0, Fp::from(36u64));
    }

    #[test]
    fn test_repeat_synthesize_trace() {
        let gadget = Repeat::<_, 3>::new(SquareGadget);
        let mut env = Trace::<Fp>::new(16);

        // Write input value
        let input_pos = env.allocate();
        let input_var = env.write_column(input_pos, Fp::from(2u64));
        let input = Scalar(input_var);

        let output = gadget.synthesize(&mut env, input);

        // 2 -> 4 -> 16 -> 256
        assert_eq!(output.0, Fp::from(256u64));
    }

    #[test]
    fn test_chain_synthesize_constraint() {
        let chain = Chain::new(DoubleGadget, SquareGadget);
        let mut env = ConstraintEnv::<Fp>::new();

        // Create input variable
        let input_pos = env.allocate();
        let input_var = env.read_position(input_pos);
        let input = Scalar(input_var);

        let _output = chain.synthesize(&mut env, input);

        // Should have allocated: input + 2 outputs (one per gadget)
        assert_eq!(env.num_witness_allocations(), 3);
    }

    #[test]
    fn test_nested_chain() {
        // (double -> square) -> double: 2 -> 4 -> 16 -> 32
        let inner = Chain::new(DoubleGadget, SquareGadget);
        let outer = Chain::new(inner, DoubleGadget);

        let input = Scalar(Fp::from(2u64));
        let output = outer.output(&input);
        assert_eq!(output.0, Fp::from(32u64));
    }

    #[test]
    fn test_chain_of_repeats() {
        // (repeat double 2x) -> (repeat square 2x): 2 -> 4 -> 8 -> 64 -> 4096
        let double_twice = Repeat::<_, 2>::new(DoubleGadget);
        let square_twice = Repeat::<_, 2>::new(SquareGadget);
        let chain = Chain::new(double_twice, square_twice);

        let input = Scalar(Fp::from(2u64));
        let output = chain.output(&input);
        assert_eq!(output.0, Fp::from(4096u64));
    }

    #[test]
    fn test_gadget_circuit_output() {
        let gadget = Repeat::<_, 3>::new(SquareGadget);
        let circuit = GadgetCircuit::new(gadget, "RepeatedSquare");

        let z = [Fp::from(2u64)];
        let output = circuit.output(&z);
        assert_eq!(output[0], Fp::from(256u64));
    }

    #[test]
    fn test_gadget_circuit_synthesize_trace() {
        let gadget = Chain::new(DoubleGadget, SquareGadget);
        let circuit = GadgetCircuit::new(gadget, "DoubleSquare");

        let mut env = Trace::<Fp>::new(16);
        let z = [Fp::from(3u64)];

        let output = circuit.synthesize(&mut env, &z);

        // 3 -> 6 -> 36
        assert_eq!(output[0], Fp::from(36u64));
    }

    #[test]
    fn test_gadget_circuit_num_rows() {
        let gadget = Repeat::<_, 5>::new(SquareGadget);
        let circuit: GadgetCircuit<Repeat<SquareGadget, 5>> = GadgetCircuit::new(gadget, "RepeatedSquare5");
        assert_eq!(StepCircuit::<Fp, 1>::num_rows(&circuit), 5);
    }
}
