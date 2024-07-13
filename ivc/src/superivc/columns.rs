pub enum SuperIVCColumn {
    /// Public selectors
    /// Selector to compute the ECC addition
    BlockAppECCAdd,
    /// Selector to compute the hash of the commitments (APP + IVC)
    /// The block will also be responsible to compute the "output" of the
    /// selected application "f_j". The block will use the state of the sponge
    /// for the specific app, and the final state of this sponge at the end of
    /// the fold will be used as a public input for the next instance.
    BlockAppHashCommitments,
    /// Selector to split the foreign field elements into chunks of 150 bits and
    /// 75 bits that can be used for the EC ADD
    BlockAppSplit,
    /// Public columns. Should be at least the number of round constants for
    /// Poseidon
    PublicColumn(usize),
    /// Any variable
    X(usize),
}

/// Compute the height of each block
/// The blocks are:
/// - foreign field elliptic curve additions
/// - computing the hash of the commitments
/// - splitting the commitments in chunks of 150 bits, 15 bits and 75 bits to be
/// used by FF EC addition and the hashes
// FIXME: the output is faked for now
pub fn compute_block_height(block_idx: usize) -> usize {
    match block_idx {
        // Block for EC ADD
        0 => 42,
        // Block for hashing the commitments
        1 => 42,
        // Block for splitting the app in different chunks
        2 => 42,
        _ => panic!("No block with index {block_idx}"),
    }
}
