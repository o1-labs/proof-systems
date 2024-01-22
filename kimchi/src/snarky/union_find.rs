use std::collections::HashMap;
use std::hash::Hash;

#[derive(Debug, Clone, Default)]
/// Tarjan's Union-Find Data structure
pub struct DisjointSet<T> {
    set_size: usize,
    /// The structure saves the parent information of each subset in continuous
    /// memory(a vec) for better performance.
    parent: Vec<usize>,

    /// Each T entry is mapped onto a usize tag.
    map: HashMap<T, usize>,
}

impl<T> DisjointSet<T>
where
    T: Clone + Hash + Eq,
{
    pub fn new() -> Self {
        DisjointSet {
            set_size: 0,
            parent: Vec::new(),
            map: HashMap::new(),
        }
    }

    pub fn make_set(&mut self, x: T) {
        let len = &mut self.set_size;
        if self.map.get(&x).is_some() {
            return;
        }

        self.map.insert(x, *len);
        self.parent.push(*len);

        *len += 1;
    }

    /// Returns Some(num), num is the tag of subset in which x is.
    /// If x is not in the data structure, it returns None.
    pub fn find(&mut self, x: T) -> Option<usize> {
        let pos = match self.map.get(&x) {
            Some(p) => *p,
            None => return None,
        };

        let ret = DisjointSet::<T>::find_internal(&mut self.parent, pos);
        Some(ret)
    }

    fn find_internal(p: &mut Vec<usize>, n: usize) -> usize {
        if p[n] != n {
            let parent = p[n];
            p[n] = DisjointSet::<T>::find_internal(p, parent);
            p[n]
        } else {
            n
        }
    }

    /// Union the subsets to which x and y belong.
    /// If it returns `Some<u32>`, it is the tag for unified subset.
    /// If it returns `None`, at least one of x and y is not in the
    /// disjoint-set.
    pub fn union(&mut self, x: T, y: T) -> Option<usize> {
        let (x_root, y_root) = match (self.find(x), self.find(y)) {
            (Some(x), Some(y)) => (x, y),
            _ => {
                return None;
            }
        };

        self.parent[x_root] = y_root;
        Some(y_root)
    }
}

#[test]
fn it_works() {
    let mut ds = DisjointSet::<i32>::new();
    ds.make_set(1);
    ds.make_set(2);
    ds.make_set(3);

    assert!(ds.find(1) != ds.find(2));
    assert!(ds.find(2) != ds.find(3));
    ds.union(1, 2).unwrap();
    ds.union(2, 3).unwrap();
    assert!(ds.find(1) == ds.find(3));

    assert!(ds.find(4).is_none());
    ds.make_set(4);
    assert!(ds.find(4).is_some());

    ds.make_set(-1);
    assert!(ds.find(-1) != ds.find(3));

    ds.union(-1, 4).unwrap();
    ds.union(2, 4).unwrap();

    assert!(ds.find(-1) == ds.find(3));
}
