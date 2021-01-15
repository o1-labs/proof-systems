#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unused_import_braces, trivial_casts, trivial_numeric_casts)]
#![deny(unused_qualifications, variant_size_differences, unused_extern_crates)]
#![deny(non_shorthand_field_patterns, unused_attributes, unused_imports)]
#![deny(renamed_and_removed_lints, unused_allocation, unused_comparisons)]
#![deny(const_err, unused_must_use, unused_mut, bare_trait_objects)]
#![forbid(unsafe_code)]

#[cfg(all(test, not(feature = "std")))]
#[macro_use]
extern crate std;

/// this crate needs to be public, cause we expose `to_bytes!` macro
/// see similar issue in [`smallvec#198`]
///
/// [`smallvec#198`]: https://github.com/servo/rust-smallvec/pull/198
#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
#[macro_use]
#[doc(hidden)]
pub extern crate alloc;

#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
#[doc(hidden)]
pub use alloc::{boxed::Box, format, string::String, vec, vec::Vec};

#[cfg(feature = "std")]
#[allow(unused_imports)]
#[doc(hidden)]
pub use std::{boxed::Box, format, vec, vec::Vec};

pub use algebra_core::*;

///////////////////////////////////////////////////////////////////////////////
#[cfg(feature = "bn_382")]
pub mod bn_382;
#[cfg(feature = "bn_382")]
pub use bn_382::Bn_382;
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
#[cfg(feature = "tweedle")]
pub mod tweedle;
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
#[cfg(feature = "pasta")]
pub mod pasta;
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
pub(crate) mod tests;
