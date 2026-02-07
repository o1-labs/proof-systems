//! This module hosts the [`AdjacentPairs`] type.
//!
//! It can be used to list all the adjacent pairs of a list.
//! For example, if you have a list of integers `[1, 2, 3]`,
//! you can use it to obtain the list of tuples `[(1, 2), (2, 3)]`.

/// You can create a new [`AdjacentPairs`] from an iterator using:
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
        if let Some(x) = self.prev_second_component {
            let y = self.i.next()?;
            self.prev_second_component = Some(y);
            Some((x, y))
        } else {
            let x = self.i.next()?;
            let y = self.i.next()?;
            self.prev_second_component = Some(y);
            Some((x, y))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_sequence() {
        let pairs: Vec<_> = AdjacentPairs::from(vec![1, 2, 3, 4]).collect();
        assert_eq!(pairs, vec![(1, 2), (2, 3), (3, 4)]);
    }

    #[test]
    fn test_two_elements() {
        let pairs: Vec<_> = AdjacentPairs::from(vec![10, 20]).collect();
        assert_eq!(pairs, vec![(10, 20)]);
    }

    #[test]
    fn test_single_element() {
        let mut pairs = AdjacentPairs::from(vec![42]);
        assert_eq!(pairs.next(), None);
    }

    #[test]
    fn test_empty() {
        let mut pairs = AdjacentPairs::from(Vec::<i32>::new());
        assert_eq!(pairs.next(), None);
    }

    #[test]
    fn test_duplicate_values() {
        let pairs: Vec<_> = AdjacentPairs::from(vec![5, 5, 5]).collect();
        assert_eq!(pairs, vec![(5, 5), (5, 5)]);
    }

    #[test]
    fn test_step_by_step_iteration() {
        let mut pairs = AdjacentPairs::from(vec![1, 2, 3]);
        assert_eq!(pairs.next(), Some((1, 2)));
        assert_eq!(pairs.next(), Some((2, 3)));
        assert_eq!(pairs.next(), None);
        // exhausted iterator stays exhausted
        assert_eq!(pairs.next(), None);
    }

    #[test]
    fn test_from_range() {
        let pairs: Vec<_> = AdjacentPairs::from(0..5).collect();
        assert_eq!(pairs, vec![(0, 1), (1, 2), (2, 3), (3, 4)]);
    }
}
