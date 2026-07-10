//! Common utility types for Mina transactions.

/// A value that is either set to a specific value or kept unchanged.
///
/// Used in zkApp account updates to indicate which fields should be
/// modified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetOrKeep<T> {
    /// Set the field to this value.
    Set(T),
    /// Keep the field unchanged.
    Keep,
}

/// A precondition that is either checked against a value or ignored.
///
/// Used in zkApp preconditions to optionally constrain fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrIgnore<T> {
    /// Check that the field matches this value.
    Check(T),
    /// Ignore this field (no constraint).
    Ignore,
}

/// A closed interval `[lower, upper]`.
///
/// Used in numeric preconditions to specify acceptable ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedInterval<T> {
    /// The lower bound (inclusive).
    pub lower: T,
    /// The upper bound (inclusive).
    pub upper: T,
}

/// A collection of exactly one or two elements.
///
/// Used for fee transfers, which can have one or two recipients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OneOrTwo<T> {
    /// Exactly one element.
    One(T),
    /// Exactly two elements.
    Two(T, T),
}

/// A hash precondition (check exact value or ignore).
pub type HashCheck<T> = OrIgnore<T>;

/// An equality-check precondition (check exact value or ignore).
pub type EqCheck<T> = OrIgnore<T>;

/// A numeric range precondition (check range or ignore).
pub type NumericCheck<T> = OrIgnore<ClosedInterval<T>>;
