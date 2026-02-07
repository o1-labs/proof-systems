//! Top-level transaction types.

extern crate alloc;
use alloc::boxed::Box;

use crate::{
    coinbase::Coinbase, fee_transfer::FeeTransfer, signed_command::SignedCommand,
    zkapp_command::ZkAppCommand,
};

/// A user-initiated command (either a signed command or a zkApp
/// command).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserCommand {
    /// A signed command (payment or stake delegation).
    SignedCommand(Box<SignedCommand>),
    /// A zkApp command (one or more account updates).
    ZkAppCommand(Box<ZkAppCommand>),
}

/// A transaction on the Mina blockchain.
///
/// Transactions can be user-initiated commands, system fee transfers,
/// or coinbase rewards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transaction {
    /// A user-initiated command.
    Command(UserCommand),
    /// A system-generated fee transfer to SNARK workers.
    FeeTransfer(FeeTransfer),
    /// A system-generated block reward.
    Coinbase(Coinbase),
}
