struct AdjacentPairs<A, I: Iterator<Item = A>> {
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

fn adjacent_pairs<A: Copy, I: Iterator<Item = A>>(i: I) -> AdjacentPairs<A, I> {
    AdjacentPairs {
        i,
        prev_second_component: None,
    }
}
