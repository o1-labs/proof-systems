/// A user state that deals only with bytes
///
/// The encoding will be trying to pack as many bytes as possible in a field
/// element.
#[derive(Debug, Clone)]
pub struct DenseState {
    pub bytes: Vec<u8>,
}
