//! This is the pickles flavor of the o1vm.
//! The goal of this flavor is to run a version of the o1vm with selectors for
//! each instruction using the Pasta curves and the IPA PCS.
//!
//! A proof is generated for each set of N continuous instructions, where N is
//! the size of the supported SRS. The proofs will then be aggregated using
//! a modified version of pickles.
//!
//! You can run this flavor by using:
//!
//! ```bash
//! O1VM_FLAVOR=pickles bash run-code.sh
//! ```

pub mod proof;

// TODO: Empty for now, but some modules like prover, verifier & co. will be
// added soon.
