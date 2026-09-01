//! Account permission types for Mina.

use crate::currency::TxnVersion;

/// Authorization level required for an account operation.
///
/// Controls what kind of authorization is needed to perform
/// specific operations on an account.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum AuthRequired {
    /// No authorization required.
    #[default]
    None,
    /// Either a signature or a proof suffices.
    Either,
    /// A zero-knowledge proof is required.
    Proof,
    /// A signature is required.
    Signature,
    /// The operation is permanently disabled.
    Impossible,
    /// Both a proof and a signature are required (legacy).
    Both,
}

/// Verification key change authorization with transaction version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetVerificationKey {
    /// The authorization level required.
    pub auth: AuthRequired,
    /// The transaction version.
    pub txn_version: TxnVersion,
}

/// Account permissions controlling which operations are allowed and
/// what authorization they require.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Permissions {
    /// Permission to modify zkApp state fields.
    pub edit_state: AuthRequired,
    /// Permission to access (read) the account in a zkApp transaction.
    pub access: AuthRequired,
    /// Permission to send tokens from this account.
    pub send: AuthRequired,
    /// Permission to receive tokens into this account.
    pub receive: AuthRequired,
    /// Permission to change the delegate.
    pub set_delegate: AuthRequired,
    /// Permission to change permissions.
    pub set_permissions: AuthRequired,
    /// Permission to change the verification key.
    pub set_verification_key: SetVerificationKey,
    /// Permission to change the zkApp URI.
    pub set_zkapp_uri: AuthRequired,
    /// Permission to modify the action state.
    pub edit_action_state: AuthRequired,
    /// Permission to change the token symbol.
    pub set_token_symbol: AuthRequired,
    /// Permission to increment the nonce.
    pub increment_nonce: AuthRequired,
    /// Permission to change the voting-for state hash.
    pub set_voting_for: AuthRequired,
    /// Permission to change the account timing.
    pub set_timing: AuthRequired,
}
