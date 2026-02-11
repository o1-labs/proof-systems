#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
// Cryptographic constants use unseparated hex literals for consistency with
// reference implementations
#![allow(clippy::unreadable_literal)]

pub mod named;
pub mod pasta;
