//! Selector type markers for type-safe gadget selection.
//!
//! This module provides compile-time type safety for gadget selectors.
//! Each gadget has a unique selector type that maps to the runtime `Gadget` enum.

use core::fmt::Debug;

use crate::column::Gadget;

/// Marker trait for selector types.
///
/// Each gadget has a unique selector type that provides:
/// - Compile-time type safety for selector access
/// - Runtime mapping to `Gadget` enum variant
/// - Unique index for polynomial evaluation
///
/// # Type Parameters
///
/// Selector types are zero-sized marker types (ZSTs) that carry
/// gadget information at the type level.
pub trait SelectorTag: 'static + Copy + Clone + Debug + Send + Sync + Default {
    /// The runtime gadget enum variant this selector corresponds to.
    const GADGET: Gadget;

    /// Human-readable name for this selector (e.g., "q_ec_add").
    const NAME: &'static str;

    /// Unique index for this selector in the polynomial evaluation.
    ///
    /// Indices are assigned as follows:
    /// - 0: NoOp
    /// - 1: EllipticCurveAddition
    /// - 2: EllipticCurveScaling
    /// - 3: PoseidonSpongeAbsorb
    /// - 4-15: PoseidonFullRound (starting rounds 0, 5, 10, ..., 55)
    const INDEX: usize;
}

// ============================================================================
// Concrete Selector Types
// ============================================================================

/// Selector for NoOp gadget (padding/no constraints).
#[derive(Debug, Clone, Copy, Default)]
pub struct QNoOp;

impl SelectorTag for QNoOp {
    const GADGET: Gadget = Gadget::NoOp;
    const NAME: &'static str = "q_noop";
    const INDEX: usize = 0;
}

/// Selector for application-defined gadget.
#[derive(Debug, Clone, Copy, Default)]
pub struct QApp;

impl SelectorTag for QApp {
    const GADGET: Gadget = Gadget::App;
    const NAME: &'static str = "q_app";
    const INDEX: usize = 1;
}

/// Selector for elliptic curve point addition.
#[derive(Debug, Clone, Copy, Default)]
pub struct QECAdd;

impl SelectorTag for QECAdd {
    const GADGET: Gadget = Gadget::EllipticCurveAddition;
    const NAME: &'static str = "q_ec_add";
    const INDEX: usize = 2;
}

/// Selector for elliptic curve scalar multiplication.
#[derive(Debug, Clone, Copy, Default)]
pub struct QECScale;

impl SelectorTag for QECScale {
    const GADGET: Gadget = Gadget::EllipticCurveScaling;
    const NAME: &'static str = "q_ec_scale";
    const INDEX: usize = 3;
}

/// Selector for Poseidon sponge absorption.
#[derive(Debug, Clone, Copy, Default)]
pub struct QPoseidonAbsorb;

impl SelectorTag for QPoseidonAbsorb {
    const GADGET: Gadget = Gadget::PoseidonSpongeAbsorb;
    const NAME: &'static str = "q_poseidon_absorb";
    const INDEX: usize = 4;
}

/// Selector for Poseidon full round at a specific starting round.
///
/// The const parameter `R` is the starting round number (must be a multiple of 5).
/// For 60-round Poseidon, valid values are 0, 5, 10, ..., 55.
///
/// # Type Parameters
///
/// - `R`: Starting round number (multiple of 5)
#[derive(Debug, Clone, Copy, Default)]
pub struct QPoseidonRound<const R: usize>;

impl<const R: usize> SelectorTag for QPoseidonRound<R> {
    const GADGET: Gadget = Gadget::PoseidonFullRound(R);
    const NAME: &'static str = "q_poseidon_round";
    // Index 5 + R/5 gives us indices 5-16 for rounds 0-55
    const INDEX: usize = 5 + R / 5;
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Total number of selector types.
///
/// This is used to size arrays and determine polynomial arity.
/// Currently: NoOp + App + ECAdd + ECScale + PoseidonAbsorb + 12 PoseidonRounds = 17
pub const NUMBER_OF_SELECTOR_TYPES: usize = 17;

/// Convert a runtime `Gadget` to its selector index.
///
/// This is the runtime equivalent of `SelectorTag::INDEX`.
pub fn gadget_to_index(gadget: Gadget) -> usize {
    match gadget {
        Gadget::NoOp => 0,
        Gadget::App => 1,
        Gadget::EllipticCurveAddition => 2,
        Gadget::EllipticCurveScaling => 3,
        Gadget::PoseidonSpongeAbsorb => 4,
        Gadget::PoseidonFullRound(starting_round) => {
            debug_assert_eq!(starting_round % 5, 0, "Starting round must be multiple of 5");
            5 + starting_round / 5
        }
    }
}

/// Convert a selector index back to a `Gadget`.
///
/// Returns `None` if the index is out of range.
pub fn index_to_gadget(index: usize) -> Option<Gadget> {
    match index {
        0 => Some(Gadget::NoOp),
        1 => Some(Gadget::App),
        2 => Some(Gadget::EllipticCurveAddition),
        3 => Some(Gadget::EllipticCurveScaling),
        4 => Some(Gadget::PoseidonSpongeAbsorb),
        5..=16 => Some(Gadget::PoseidonFullRound((index - 5) * 5)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selector_indices_unique() {
        // Verify all selector indices are unique and within range
        let indices = [
            QNoOp::INDEX,
            QApp::INDEX,
            QECAdd::INDEX,
            QECScale::INDEX,
            QPoseidonAbsorb::INDEX,
            QPoseidonRound::<0>::INDEX,
            QPoseidonRound::<5>::INDEX,
            QPoseidonRound::<10>::INDEX,
            QPoseidonRound::<15>::INDEX,
            QPoseidonRound::<20>::INDEX,
            QPoseidonRound::<25>::INDEX,
            QPoseidonRound::<30>::INDEX,
            QPoseidonRound::<35>::INDEX,
            QPoseidonRound::<40>::INDEX,
            QPoseidonRound::<45>::INDEX,
            QPoseidonRound::<50>::INDEX,
            QPoseidonRound::<55>::INDEX,
        ];

        // Check uniqueness
        let mut sorted = indices.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), indices.len(), "Selector indices must be unique");

        // Check range
        for &idx in &indices {
            assert!(idx < NUMBER_OF_SELECTOR_TYPES, "Index {} out of range", idx);
        }
    }

    #[test]
    fn test_gadget_to_index_roundtrip() {
        let gadgets = [
            Gadget::NoOp,
            Gadget::App,
            Gadget::EllipticCurveAddition,
            Gadget::EllipticCurveScaling,
            Gadget::PoseidonSpongeAbsorb,
            Gadget::PoseidonFullRound(0),
            Gadget::PoseidonFullRound(5),
            Gadget::PoseidonFullRound(55),
        ];

        for gadget in gadgets {
            let index = gadget_to_index(gadget);
            let recovered = index_to_gadget(index).expect("Should recover gadget");
            assert_eq!(gadget, recovered, "Roundtrip failed for {:?}", gadget);
        }
    }

    #[test]
    fn test_selector_tag_matches_gadget_index() {
        // Verify that SelectorTag::INDEX matches gadget_to_index for each type
        assert_eq!(QNoOp::INDEX, gadget_to_index(QNoOp::GADGET));
        assert_eq!(QApp::INDEX, gadget_to_index(QApp::GADGET));
        assert_eq!(QECAdd::INDEX, gadget_to_index(QECAdd::GADGET));
        assert_eq!(QECScale::INDEX, gadget_to_index(QECScale::GADGET));
        assert_eq!(QPoseidonAbsorb::INDEX, gadget_to_index(QPoseidonAbsorb::GADGET));
        assert_eq!(
            QPoseidonRound::<0>::INDEX,
            gadget_to_index(QPoseidonRound::<0>::GADGET)
        );
        assert_eq!(
            QPoseidonRound::<55>::INDEX,
            gadget_to_index(QPoseidonRound::<55>::GADGET)
        );
    }
}
