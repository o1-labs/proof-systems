//! This submodule provides the legacy flavor/interface of the o1vm, and is not
//! supposed to be used anymore.
//!
//! This o1vm flavor was supposed to use the [folding](folding) library defined
//! in [folding](folding), which consists of reducing all constraints to degree
//! 2, in addition to the `ivc` library defined in this monorepo to support long
//! traces.
//! The goal of this flavor was to support the curve `bn254`. For the time
//! being, the project has been stopped in favor of the pickles version defined
//! in [crate::pickles] and we do not aim to provide any support for now.
//!
//! You can still run the legacy flavor by using:
//!
//! ```bash
//! O1VM_FLAVOR=legacy bash run-code.sh
//! ```

pub mod folding;
pub mod proof;
pub mod trace;
