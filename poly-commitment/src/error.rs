use thiserror::Error;

#[derive(Error, Debug, Clone, Copy)]
pub enum CommitmentError {
    #[error(
        "the length of the given blinders ({0}) doesn't match the length of the commitment ({1})"
    )]
    BlindersDontMatch(usize, usize),
}
