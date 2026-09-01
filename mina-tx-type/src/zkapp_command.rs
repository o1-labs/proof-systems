//! zkApp command types.

extern crate alloc;

use alloc::vec::Vec;

use mina_curves::pasta::Fp;
use mina_signer::{CompressedPubKey, Signature};

use crate::{
    common::SetOrKeep,
    currency::{Amount, Balance, Fee, Nonce, Slot, SlotSpan},
    permissions::Permissions,
    preconditions::Preconditions,
    primitives::{Memo, TokenId, TokenSymbol, VotingFor, ZkAppUri},
};

/// Vesting timing parameters for an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timing {
    /// Initial minimum balance that is locked.
    pub initial_minimum_balance: Balance,
    /// Slot at which the cliff occurs.
    pub cliff_time: Slot,
    /// Amount released at the cliff.
    pub cliff_amount: Amount,
    /// Period between vesting increments.
    pub vesting_period: SlotSpan,
    /// Amount released per vesting period.
    pub vesting_increment: Amount,
}

/// How many proofs a verification key can verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofVerified {
    /// Zero proofs.
    N0,
    /// One proof.
    N1,
    /// Two proofs.
    N2,
}

/// A verification key for zkApp proof verification.
///
/// This is a simplified representation. The full verification key
/// contains PLONK polynomial commitment points, but here we store
/// only the metadata and raw data needed for identification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationKey {
    /// Maximum number of proofs this key can verify.
    pub max_proofs_verified: ProofVerified,
    /// Actual wrap domain size.
    pub actual_wrap_domain_size: ProofVerified,
    /// Raw verification key data (serialized PLONK evaluation points).
    pub wrap_index: Vec<u8>,
}

/// An event: a list of field elements emitted by a zkApp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event(pub Vec<Fp>);

/// A collection of events emitted by a zkApp account update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Events(pub Vec<Event>);

/// A collection of actions (sequenced events) emitted by a zkApp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actions(pub Vec<Event>);

/// The set of fields that an account update can modify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    /// zkApp state fields (8 field elements).
    pub app_state: [SetOrKeep<Fp>; 8],
    /// Delegate public key.
    pub delegate: SetOrKeep<CompressedPubKey>,
    /// Verification key for proof authorization.
    pub verification_key: SetOrKeep<VerificationKey>,
    /// Account permissions.
    pub permissions: SetOrKeep<Permissions>,
    /// zkApp URI.
    pub zkapp_uri: SetOrKeep<ZkAppUri>,
    /// Token symbol.
    pub token_symbol: SetOrKeep<TokenSymbol>,
    /// Account timing (vesting schedule).
    pub timing: SetOrKeep<Timing>,
    /// Protocol state hash the account votes for.
    pub voting_for: SetOrKeep<VotingFor>,
}

/// Whether a zkApp account update may use a parent's token.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MayUseToken {
    /// May not use any parent token.
    No,
    /// May use the immediate parent's own token.
    ParentsOwnToken,
    /// Inherits token permission from parent.
    InheritFromParent,
}

/// The kind of authorization used for an account update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationKind {
    /// No authorization.
    NoneGiven,
    /// Authorized by signature.
    Signature,
    /// Authorized by proof (carries the verification key hash).
    Proof(Fp),
}

/// Authorization control for an account update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    /// Authorized by a zero-knowledge proof (opaque proof bytes).
    Proof(Vec<u8>),
    /// Authorized by a cryptographic signature.
    Signature(Signature),
    /// No authorization provided.
    NoneGiven,
}

/// The body of a zkApp account update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountUpdateBody {
    /// The account's public key.
    pub public_key: CompressedPubKey,
    /// The token for this account.
    pub token_id: TokenId,
    /// Fields to update.
    pub update: Update,
    /// Balance change (positive = credit, negative = debit).
    pub balance_change: crate::currency::Signed<Amount>,
    /// Whether to increment the account nonce.
    pub increment_nonce: bool,
    /// Events emitted by this account update.
    pub events: Events,
    /// Actions (sequenced events) emitted by this account update.
    pub actions: Actions,
    /// Opaque call data (field element).
    pub call_data: Fp,
    /// Preconditions that must hold for this update to apply.
    pub preconditions: Preconditions,
    /// Whether to use the full transaction commitment for signing.
    pub use_full_commitment: bool,
    /// Whether this update implicitly pays the account creation fee.
    pub implicit_account_creation_fee: bool,
    /// Token usage permission.
    pub may_use_token: MayUseToken,
    /// The kind of authorization used.
    pub authorization_kind: AuthorizationKind,
}

/// A single account update with its authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountUpdate {
    /// The account update body.
    pub body: AccountUpdateBody,
    /// The authorization (proof, signature, or none).
    pub authorization: Control,
}

/// A node in the account update tree.
///
/// Each node contains an account update and its nested child calls,
/// forming a tree structure that represents the call graph of a
/// zkApp transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountUpdateTree {
    /// The account update at this node.
    pub account_update: AccountUpdate,
    /// Child account updates called by this node.
    pub children: Vec<Self>,
}

/// The fee payer body for a zkApp command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeePayerBody {
    /// The fee payer's public key.
    pub public_key: CompressedPubKey,
    /// The transaction fee.
    pub fee: Fee,
    /// Optional slot after which the transaction expires.
    pub valid_until: Option<Slot>,
    /// The fee payer's account nonce.
    pub nonce: Nonce,
}

/// The fee payer of a zkApp command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeePayer {
    /// Fee payer details.
    pub body: FeePayerBody,
    /// Signature authorizing the fee payment.
    pub authorization: Signature,
}

/// A zkApp command: a transaction containing one or more account
/// updates.
///
/// A zkApp command consists of a fee payer (who pays the transaction
/// fee), a tree of account updates (the actual operations), and an
/// optional memo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkAppCommand {
    /// The fee payer for this transaction.
    pub fee_payer: FeePayer,
    /// The account update tree (call forest).
    pub account_updates: Vec<AccountUpdateTree>,
    /// Optional memo.
    pub memo: Memo,
}
