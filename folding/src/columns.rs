/// This module contains description of the additional columns used by our
/// folding scheme implementation. The columns are the base layer of the folding
/// scheme as they describe the basic expressiveness of the system.
use ark_ec::AffineCurve;
use kimchi::circuits::expr::Variable;

use crate::FoldingConfig;

/// Describes the additional columns. It is parametrized by a configuration for
/// the folding scheme, described in the trait [FoldingConfig]. For instance,
/// the configuration describes the initial columns of the circuit, the
/// challenges and the underlying field.
pub enum ExtendedFoldingColumn<C: FoldingConfig> {
    Inner(Variable<C::Column>),
    /// For the extra columns added by the module `quadraticization`.
    WitnessExtended(usize),
    /// The error term introduced in the "relaxed" instance.
    Error,
    Constant(<C::Curve as AffineCurve>::ScalarField),
    /// A challenge used by the PIOP or the folding scheme.
    Challenge(C::Challenge),
    /// A list of randomizer to combine expressions
    Alpha(usize),
    /// A "virtual" selector that can be used to activate/deactivate expressions
    /// while folding/accumulating multiple expressions.
    Selector(C::Selector),
}

impl<C: FoldingConfig> std::hash::Hash for ExtendedFoldingColumn<C> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
    }
}

impl<C: FoldingConfig> std::fmt::Debug for ExtendedFoldingColumn<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inner(arg0) => f.debug_tuple("Inner").field(arg0).finish(),
            Self::WitnessExtended(arg0) => f.debug_tuple("WitnessExtended").field(arg0).finish(),
            Self::Error => write!(f, "Error"),
            Self::Constant(arg0) => f.debug_tuple("Constant").field(arg0).finish(),
            Self::Challenge(arg0) => f.debug_tuple("Challenge").field(arg0).finish(),
            Self::Alpha(arg0) => f.debug_tuple("Alpha").field(arg0).finish(),
            Self::Selector(arg0) => f.debug_tuple("Selector").field(arg0).finish(),
        }
    }
}

impl<C: FoldingConfig> Clone for ExtendedFoldingColumn<C> {
    fn clone(&self) -> Self {
        match self {
            Self::Inner(arg0) => Self::Inner(arg0.clone()),
            Self::WitnessExtended(arg0) => Self::WitnessExtended(arg0.clone()),
            Self::Error => Self::Error,
            Self::Constant(arg0) => Self::Constant(arg0.clone()),
            Self::Challenge(arg0) => Self::Challenge(arg0.clone()),
            Self::Alpha(arg0) => Self::Alpha(arg0.clone()),
            Self::Selector(arg0) => Self::Selector(arg0.clone()),
        }
    }
}

impl<C: FoldingConfig> Eq for ExtendedFoldingColumn<C> {}

impl<C: FoldingConfig> PartialEq for ExtendedFoldingColumn<C> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Inner(l0), Self::Inner(r0)) => l0 == r0,
            (Self::WitnessExtended(l0), Self::WitnessExtended(r0)) => l0 == r0,
            (Self::Constant(l0), Self::Constant(r0)) => l0 == r0,
            (Self::Challenge(l0), Self::Challenge(r0)) => l0 == r0,
            (Self::Alpha(l0), Self::Alpha(r0)) => l0 == r0,
            (Self::Selector(l0), Self::Selector(r0)) => l0 == r0,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}
