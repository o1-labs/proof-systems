use crate::FoldingConfig;
/// This module contains description of the additional columns used by our
/// folding scheme implementation. The columns are the base layer of the folding
/// scheme as they describe the basic expressiveness of the system.
use ark_ec::AffineCurve;
use derivative::Derivative;
use kimchi::circuits::expr::Variable;

/// Describes the additional columns. It is parametrized by a configuration for
/// the folding scheme, described in the trait [FoldingConfig]. For instance,
/// the configuration describes the initial columns of the circuit, the
/// challenges and the underlying field.
#[derive(Derivative)]
#[derivative(
    Hash(bound = "C: FoldingConfig"),
    Debug(bound = "C: FoldingConfig"),
    Clone(bound = "C: FoldingConfig"),
    PartialEq(bound = "C: FoldingConfig"),
    Eq(bound = "C: FoldingConfig")
)]
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
