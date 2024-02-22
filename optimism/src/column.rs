/// The witness columns used by a gate of the zkVM circuit.
/// It is generic over the number of columns, N, and the type of the witness, T.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Witness<const N: usize, T> {
    /// A witness row is represented by an array of N witness columns
    pub row: [T; N],
}
