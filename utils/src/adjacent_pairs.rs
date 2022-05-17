//! This module hosts the [AdjacentPairs] type,
//! which can be used to list all the adjacent pairs of a list.
//! For example, if you have a list of integers `[1, 2, 3]`,
//! you can use it to obtain the list of tuples `[(1, 2), (2, 3)]`.

/// You can create a new [AdjacentPairs] from an iterator using:
///
/// ```
/// use o1_utils::adjacent_pairs::AdjacentPairs;
///
/// let a = vec![1, 2, 3];
/// let mut pairs = AdjacentPairs::from(a);
///
/// assert_eq!(pairs.next(), Some((1, 2)));
/// assert_eq!(pairs.next(), Some((2, 3)));
/// assert_eq!(pairs.next(), None);
/// ```
pub struct AdjacentPairs<A, I>
where
    I: Iterator<Item = A>,
{
    prev_second_component: Option<A>,
    i: I,
}

impl<A: Copy, I: Iterator<Item = A>> Iterator for AdjacentPairs<A, I> {
    type Item = (A, A);

    fn next(&mut self) -> Option<(A, A)> {
        match self.prev_second_component {
            Some(x) => match self.i.next() {
                None => None,
                Some(y) => {
                    self.prev_second_component = Some(y);
                    Some((x, y))
                }
            },
            None => {
                let x = self.i.next();
                let y = self.i.next();
                match (x, y) {
                    (None, _) | (_, None) => None,
                    (Some(x), Some(y)) => {
                        self.prev_second_component = Some(y);
                        Some((x, y))
                    }
                }
            }
        }
    }
}

impl<A, I, T> From<T> for AdjacentPairs<A, I>
where
    T: IntoIterator<Item = A, IntoIter = I>,
    I: Iterator<Item = A>,
{
    fn from(i: T) -> Self {
        Self {
            i: i.into_iter(),
            prev_second_component: None,
        }
    }
}
