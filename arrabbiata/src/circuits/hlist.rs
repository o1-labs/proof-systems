//! Heterogeneous list (HList) for type-safe gadget sequences.
//!
//! This module provides a compile-time heterogeneous list that preserves
//! the exact type of each gadget in a circuit sequence.
//!
//! ## Design
//!
//! An HList is a recursive type-level list:
//! - `HNil` - Empty list
//! - `HCons<H, T>` - A head element `H` followed by tail `T`
//!
//! For example, `HCons<Squaring, HCons<Fibonacci, HNil>>` represents
//! a sequence of [Squaring, Fibonacci].
//!
//! ## Example
//!
//! ```
//! use arrabbiata::circuits::hlist::{HNil, HCons, GadgetList};
//! use arrabbiata::circuits::{SquaringGadget, FibonacciGadget};
//!
//! // Build a typed gadget sequence
//! let circuit = HNil
//!     .push(SquaringGadget::new())
//!     .push(SquaringGadget::new())
//!     .push(FibonacciGadget::new());
//!
//! // Type is: HCons<FibonacciGadget, HCons<SquaringGadget, HCons<SquaringGadget, HNil>>>
//! assert_eq!(circuit.len(), 3);
//! ```

use ark_ff::PrimeField;
use core::fmt::Debug;

use crate::{
    circuits::{gadget::TypedGadget, selector::SelectorTag},
    nifs::column::Gadget,
};

// ============================================================================
// HList Core Types
// ============================================================================

/// Empty heterogeneous list (base case).
#[derive(Clone, Debug, Default)]
pub struct HNil;

/// Non-empty heterogeneous list: head element followed by tail.
#[derive(Clone, Debug)]
pub struct HCons<H, T> {
    pub head: H,
    pub tail: T,
}

// ============================================================================
// GadgetList Trait - Common interface for gadget sequences
// ============================================================================

/// Trait for heterogeneous lists of gadgets.
///
/// This provides a common interface for operations on gadget sequences,
/// regardless of the specific types in the list.
pub trait GadgetList: Clone + Debug {
    /// Number of gadgets in the list.
    const LEN: usize;

    /// Total number of rows across all gadgets.
    fn total_rows(&self) -> usize;

    /// Get the length of this list.
    fn len(&self) -> usize {
        Self::LEN
    }

    /// Check if the list is empty.
    fn is_empty(&self) -> bool {
        Self::LEN == 0
    }

    /// Push a new gadget onto the front of the list.
    fn push<G>(self, gadget: G) -> HCons<G, Self>
    where
        Self: Sized,
    {
        HCons {
            head: gadget,
            tail: self,
        }
    }
}

impl GadgetList for HNil {
    const LEN: usize = 0;

    fn total_rows(&self) -> usize {
        0
    }
}

impl<H, T: GadgetList> GadgetList for HCons<H, T>
where
    H: Clone + Debug,
{
    const LEN: usize = 1 + T::LEN;

    fn total_rows(&self) -> usize {
        // We need H to be a TypedGadget to get ROWS, but we can't
        // express that constraint here without more complex bounds.
        // For now, we'll use a separate trait for this.
        1 + self.tail.total_rows()
    }
}

// ============================================================================
// TypedGadgetList - HList where all elements are TypedGadgets
// ============================================================================

/// Trait for heterogeneous lists where all elements are `TypedGadget`.
pub trait TypedGadgetList<F: PrimeField>: GadgetList {
    /// Get the gadget type at each position.
    fn gadgets(&self) -> Vec<Gadget>;

    /// Total rows accounting for each gadget's ROWS constant.
    fn typed_total_rows(&self) -> usize;
}

impl<F: PrimeField> TypedGadgetList<F> for HNil {
    fn gadgets(&self) -> Vec<Gadget> {
        Vec::new()
    }

    fn typed_total_rows(&self) -> usize {
        0
    }
}

impl<F, H, T> TypedGadgetList<F> for HCons<H, T>
where
    F: PrimeField,
    H: TypedGadget<F>,
    T: TypedGadgetList<F>,
{
    fn gadgets(&self) -> Vec<Gadget> {
        let mut result = vec![H::Selector::GADGET];
        result.extend(self.tail.gadgets());
        result
    }

    fn typed_total_rows(&self) -> usize {
        H::ROWS + self.tail.typed_total_rows()
    }
}

// ============================================================================
// Builder helpers
// ============================================================================

/// Start building a gadget sequence.
pub fn gadgets() -> HNil {
    HNil
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::gadgets::{CubicGadget, SquaringGadget, TrivialGadget};
    use mina_curves::pasta::Fp;

    #[test]
    fn test_hnil() {
        let empty = HNil;
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
        assert_eq!(empty.total_rows(), 0);
    }

    #[test]
    fn test_hcons_len() {
        let one = HNil.push(SquaringGadget::new());
        assert_eq!(one.len(), 1);
        assert!(!one.is_empty());

        let two = one.push(SquaringGadget::new());
        assert_eq!(two.len(), 2);

        let three = two.push(CubicGadget::new());
        assert_eq!(three.len(), 3);
    }

    #[test]
    fn test_typed_gadget_list_gadgets() {
        let circuit = HNil
            .push(SquaringGadget::new())
            .push(CubicGadget::new())
            .push(TrivialGadget::new());

        let gadgets = TypedGadgetList::<Fp>::gadgets(&circuit);
        assert_eq!(gadgets.len(), 3);
        // Note: order is reversed because push prepends
        assert_eq!(gadgets[0], Gadget::Trivial);
        assert_eq!(gadgets[1], Gadget::Cubic);
        assert_eq!(gadgets[2], Gadget::Squaring);
    }

    #[test]
    fn test_typed_total_rows() {
        let circuit = HNil
            .push(SquaringGadget::new())
            .push(SquaringGadget::new())
            .push(SquaringGadget::new());

        assert_eq!(TypedGadgetList::<Fp>::typed_total_rows(&circuit), 3);
    }

    #[test]
    fn test_builder_helper() {
        let circuit = gadgets()
            .push(SquaringGadget::new())
            .push(SquaringGadget::new());

        assert_eq!(circuit.len(), 2);
    }
}
