//! Selector trait and utility functions.
//!
//! This module provides:
//! - The `SelectorTag` trait that all gadget selectors implement
//! - Utility functions for gadget-to-index conversion
//! - Total count of selector types for polynomial sizing
//!
//! Each gadget defines its own selector type in its module, implementing
//! `SelectorTag` to map to the corresponding `Gadget` enum variant.

use core::fmt::Debug;

use crate::column::Gadget;

// ============================================================================
// SelectorTag Trait
// ============================================================================

/// Marker trait for selector types.
///
/// Each gadget has a unique selector type that provides:
/// - Compile-time type safety for selector access
/// - Runtime mapping to `Gadget` enum variant
/// - Unique index for polynomial evaluation
///
/// # Implementing for a Gadget
///
/// ```
/// use arrabbiata::circuits::selector::SelectorTag;
/// use arrabbiata::column::Gadget;
///
/// #[derive(Clone, Copy, Debug, Default)]
/// pub struct QSquaring;
///
/// impl SelectorTag for QSquaring {
///     const GADGET: Gadget = Gadget::Squaring;
///     const NAME: &'static str = "q_squaring";
///     const INDEX: usize = 2;
/// }
/// ```
pub trait SelectorTag: 'static + Copy + Clone + Debug + Send + Sync + Default {
    /// The runtime gadget enum variant this selector corresponds to.
    const GADGET: Gadget;

    /// Human-readable name for this selector (e.g., "q_squaring").
    const NAME: &'static str;

    /// Unique index for this selector in the polynomial evaluation.
    /// Must match the `From<Gadget> for usize` implementation.
    const INDEX: usize;
}

// ============================================================================
// Common Selectors (for non-gadget circuits or padding)
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

/// Selector for squaring gadget.
#[derive(Debug, Clone, Copy, Default)]
pub struct QSquaring;

impl SelectorTag for QSquaring {
    const GADGET: Gadget = Gadget::Squaring;
    const NAME: &'static str = "q_squaring";
    const INDEX: usize = 2;
}

/// Selector for cubic gadget.
#[derive(Debug, Clone, Copy, Default)]
pub struct QCubic;

impl SelectorTag for QCubic {
    const GADGET: Gadget = Gadget::Cubic;
    const NAME: &'static str = "q_cubic";
    const INDEX: usize = 3;
}

/// Selector for trivial gadget (no constraints).
#[derive(Debug, Clone, Copy, Default)]
pub struct QTrivial;

impl SelectorTag for QTrivial {
    const GADGET: Gadget = Gadget::Trivial;
    const NAME: &'static str = "q_trivial";
    const INDEX: usize = 4;
}

/// Selector for counter gadget.
#[derive(Debug, Clone, Copy, Default)]
pub struct QCounter;

impl SelectorTag for QCounter {
    const GADGET: Gadget = Gadget::Counter;
    const NAME: &'static str = "q_counter";
    const INDEX: usize = 5;
}

/// Selector for Fibonacci gadget.
#[derive(Debug, Clone, Copy, Default)]
pub struct QFibonacci;

impl SelectorTag for QFibonacci {
    const GADGET: Gadget = Gadget::Fibonacci;
    const NAME: &'static str = "q_fibonacci";
    const INDEX: usize = 6;
}

/// Selector for MinRoot VDF gadget.
#[derive(Debug, Clone, Copy, Default)]
pub struct QMinRoot;

impl SelectorTag for QMinRoot {
    const GADGET: Gadget = Gadget::MinRoot;
    const NAME: &'static str = "q_minroot";
    const INDEX: usize = 7;
}

/// Selector for elliptic curve point addition.
#[derive(Debug, Clone, Copy, Default)]
pub struct QECAdd;

impl SelectorTag for QECAdd {
    const GADGET: Gadget = Gadget::EllipticCurveAddition;
    const NAME: &'static str = "q_ec_add";
    const INDEX: usize = 8;
}

/// Selector for elliptic curve scalar multiplication.
#[derive(Debug, Clone, Copy, Default)]
pub struct QECScale;

impl SelectorTag for QECScale {
    const GADGET: Gadget = Gadget::EllipticCurveScaling;
    const NAME: &'static str = "q_ec_scale";
    const INDEX: usize = 9;
}

/// Selector for Poseidon sponge absorption.
#[derive(Debug, Clone, Copy, Default)]
pub struct QPoseidonAbsorb;

impl SelectorTag for QPoseidonAbsorb {
    const GADGET: Gadget = Gadget::PoseidonSpongeAbsorb;
    const NAME: &'static str = "q_poseidon_absorb";
    const INDEX: usize = 10;
}

/// Selector for Poseidon full round at a specific starting round.
///
/// The const parameter `R` is the starting round number (must be a multiple of 5).
/// For 60-round Poseidon, valid values are 0, 5, 10, ..., 55.
#[derive(Debug, Clone, Copy, Default)]
pub struct QPoseidonRound<const R: usize>;

impl<const R: usize> SelectorTag for QPoseidonRound<R> {
    const GADGET: Gadget = Gadget::PoseidonFullRound(R);
    const NAME: &'static str = "q_poseidon_round";
    // Index 11 + R/5 gives us indices 11-22 for rounds 0-55
    const INDEX: usize = 11 + R / 5;
}

/// Selector for Poseidon Kimchi full round at a specific starting round.
///
/// The const parameter `R` is the starting round number (must be a multiple of 5).
/// For 55-round Poseidon Kimchi, valid values are 0, 5, 10, ..., 50.
#[derive(Debug, Clone, Copy, Default)]
pub struct QPoseidonKimchiRound<const R: usize>;

impl<const R: usize> SelectorTag for QPoseidonKimchiRound<R> {
    const GADGET: Gadget = Gadget::PoseidonKimchiFullRound(R);
    const NAME: &'static str = "q_poseidon_kimchi_round";
    // Index 23 + R/5 gives us indices 23-33 for rounds 0-50
    const INDEX: usize = 23 + R / 5;
}

/// Selector for Schnorr signature verification.
#[derive(Debug, Clone, Copy, Default)]
pub struct QSchnorrVerify;

impl SelectorTag for QSchnorrVerify {
    const GADGET: Gadget = Gadget::SchnorrVerify;
    const NAME: &'static str = "q_schnorr_verify";
    const INDEX: usize = 34;
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Total number of selector types.
///
/// This is used to size arrays and determine polynomial arity.
/// Currently:
/// - NoOp (0)
/// - App (1)
/// - Squaring (2)
/// - Cubic (3)
/// - Trivial (4)
/// - Counter (5)
/// - Fibonacci (6)
/// - MinRoot (7)
/// - ECAdd (8)
/// - ECScale (9)
/// - PoseidonAbsorb (10)
/// - PoseidonRound x12 (11-22)
/// - PoseidonKimchiRound x11 (23-33)
/// - SchnorrVerify (34)
///
/// Total: 35
pub const NUMBER_OF_SELECTOR_TYPES: usize = 35;

/// Convert a runtime `Gadget` to its selector index.
///
/// This is the runtime equivalent of `SelectorTag::INDEX`.
pub fn gadget_to_index(gadget: Gadget) -> usize {
    match gadget {
        Gadget::NoOp => 0,
        Gadget::App => 1,
        Gadget::Squaring => 2,
        Gadget::Cubic => 3,
        Gadget::Trivial => 4,
        Gadget::Counter => 5,
        Gadget::Fibonacci => 6,
        Gadget::MinRoot => 7,
        Gadget::EllipticCurveAddition => 8,
        Gadget::EllipticCurveScaling => 9,
        Gadget::PoseidonSpongeAbsorb => 10,
        Gadget::PoseidonFullRound(starting_round) => {
            debug_assert!(
                starting_round.is_multiple_of(5),
                "Starting round must be multiple of 5"
            );
            11 + starting_round / 5
        }
        Gadget::PoseidonKimchiFullRound(starting_round) => {
            debug_assert!(
                starting_round.is_multiple_of(5),
                "Starting round must be multiple of 5"
            );
            23 + starting_round / 5
        }
        Gadget::SchnorrVerify => 34,
    }
}

/// Convert a selector index back to a `Gadget`.
///
/// Returns `None` if the index is out of range.
pub fn index_to_gadget(index: usize) -> Option<Gadget> {
    match index {
        0 => Some(Gadget::NoOp),
        1 => Some(Gadget::App),
        2 => Some(Gadget::Squaring),
        3 => Some(Gadget::Cubic),
        4 => Some(Gadget::Trivial),
        5 => Some(Gadget::Counter),
        6 => Some(Gadget::Fibonacci),
        7 => Some(Gadget::MinRoot),
        8 => Some(Gadget::EllipticCurveAddition),
        9 => Some(Gadget::EllipticCurveScaling),
        10 => Some(Gadget::PoseidonSpongeAbsorb),
        11..=22 => Some(Gadget::PoseidonFullRound((index - 11) * 5)),
        23..=33 => Some(Gadget::PoseidonKimchiFullRound((index - 23) * 5)),
        34 => Some(Gadget::SchnorrVerify),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selector_indices_match_gadget() {
        // Verify that SelectorTag::INDEX matches gadget_to_index
        assert_eq!(QNoOp::INDEX, gadget_to_index(QNoOp::GADGET));
        assert_eq!(QApp::INDEX, gadget_to_index(QApp::GADGET));
        assert_eq!(QSquaring::INDEX, gadget_to_index(QSquaring::GADGET));
        assert_eq!(QCubic::INDEX, gadget_to_index(QCubic::GADGET));
        assert_eq!(QTrivial::INDEX, gadget_to_index(QTrivial::GADGET));
        assert_eq!(QCounter::INDEX, gadget_to_index(QCounter::GADGET));
        assert_eq!(QFibonacci::INDEX, gadget_to_index(QFibonacci::GADGET));
        assert_eq!(QMinRoot::INDEX, gadget_to_index(QMinRoot::GADGET));
        assert_eq!(QECAdd::INDEX, gadget_to_index(QECAdd::GADGET));
        assert_eq!(QECScale::INDEX, gadget_to_index(QECScale::GADGET));
        assert_eq!(
            QPoseidonAbsorb::INDEX,
            gadget_to_index(QPoseidonAbsorb::GADGET)
        );
        assert_eq!(
            QPoseidonRound::<0>::INDEX,
            gadget_to_index(QPoseidonRound::<0>::GADGET)
        );
        assert_eq!(
            QPoseidonRound::<55>::INDEX,
            gadget_to_index(QPoseidonRound::<55>::GADGET)
        );
        // Kimchi selectors
        assert_eq!(
            QPoseidonKimchiRound::<0>::INDEX,
            gadget_to_index(QPoseidonKimchiRound::<0>::GADGET)
        );
        assert_eq!(
            QPoseidonKimchiRound::<50>::INDEX,
            gadget_to_index(QPoseidonKimchiRound::<50>::GADGET)
        );
        // Schnorr
        assert_eq!(
            QSchnorrVerify::INDEX,
            gadget_to_index(QSchnorrVerify::GADGET)
        );
    }

    #[test]
    fn test_gadget_to_index_roundtrip() {
        let gadgets = [
            Gadget::NoOp,
            Gadget::App,
            Gadget::Squaring,
            Gadget::Cubic,
            Gadget::Trivial,
            Gadget::Counter,
            Gadget::Fibonacci,
            Gadget::MinRoot,
            Gadget::EllipticCurveAddition,
            Gadget::EllipticCurveScaling,
            Gadget::PoseidonSpongeAbsorb,
            Gadget::PoseidonFullRound(0),
            Gadget::PoseidonFullRound(5),
            Gadget::PoseidonFullRound(55),
            Gadget::PoseidonKimchiFullRound(0),
            Gadget::PoseidonKimchiFullRound(5),
            Gadget::PoseidonKimchiFullRound(50),
            Gadget::SchnorrVerify,
        ];

        for gadget in gadgets {
            let index = gadget_to_index(gadget);
            let recovered = index_to_gadget(index).expect("Should recover gadget");
            assert_eq!(gadget, recovered, "Roundtrip failed for {:?}", gadget);
        }
    }

    #[test]
    fn test_all_indices_in_range() {
        for i in 0..NUMBER_OF_SELECTOR_TYPES {
            assert!(
                index_to_gadget(i).is_some(),
                "Index {} should map to a gadget",
                i
            );
        }
    }
}
