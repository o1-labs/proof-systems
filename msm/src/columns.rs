/// Describe a generic indexed variable X_{i}.
#[derive(Clone, Copy, Debug)]
pub enum Column {
    X(usize),
}
