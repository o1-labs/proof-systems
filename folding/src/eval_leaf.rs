#[derive(Clone, Debug)]
/// Result of a folding expression evaluation.
pub enum EvalLeaf<'a, F> {
    Const(F),
    Col(&'a [F]), // slice will suffice
    Result(Vec<F>),
}

impl<F: core::fmt::Display> core::fmt::Display for EvalLeaf<'_, F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let slice = match self {
            EvalLeaf::Const(c) => {
                write!(f, "Const: {}", c)?;
                return Ok(());
            }
            EvalLeaf::Col(a) => a,
            EvalLeaf::Result(a) => a.as_slice(),
        };
        writeln!(f, "[")?;
        for e in slice.iter() {
            writeln!(f, "{e}")?;
        }
        write!(f, "]")?;
        Ok(())
    }
}

impl<F: core::ops::Add<Output = F> + Clone> core::ops::Add for EvalLeaf<'_, F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self::bin_op(|a, b| a + b, self, rhs)
    }
}

impl<F: core::ops::Sub<Output = F> + Clone> core::ops::Sub for EvalLeaf<'_, F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self::bin_op(|a, b| a - b, self, rhs)
    }
}

impl<F: core::ops::Mul<Output = F> + Clone> core::ops::Mul for EvalLeaf<'_, F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self::bin_op(|a, b| a * b, self, rhs)
    }
}

impl<F: core::ops::Mul<Output = F> + Clone> core::ops::Mul<F> for EvalLeaf<'_, F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self {
        self * Self::Const(rhs)
    }
}

impl<F: Clone> EvalLeaf<'_, F> {
    pub fn map<M: Fn(&F) -> F, I: Fn(&mut F)>(self, map: M, in_place: I) -> Self {
        use EvalLeaf::*;
        match self {
            Const(c) => Const(map(&c)),
            Col(col) => {
                let res = col.iter().map(map).collect();
                Result(res)
            }
            Result(mut col) => {
                for cell in col.iter_mut() {
                    in_place(cell);
                }
                Result(col)
            }
        }
    }

    fn bin_op<M: Fn(F, F) -> F>(f: M, a: Self, b: Self) -> Self {
        use EvalLeaf::*;
        match (a, b) {
            (Const(a), Const(b)) => Const(f(a, b)),
            (Const(a), Col(b)) => {
                let res = b.iter().map(|b| f(a.clone(), b.clone())).collect();
                Result(res)
            }
            (Col(a), Const(b)) => {
                let res = a.iter().map(|a| f(a.clone(), b.clone())).collect();
                Result(res)
            }
            (Col(a), Col(b)) => {
                let res = (a.iter())
                    .zip(b.iter())
                    .map(|(a, b)| f(a.clone(), b.clone()))
                    .collect();
                Result(res)
            }
            (Result(mut a), Const(b)) => {
                for a in a.iter_mut() {
                    *a = f(a.clone(), b.clone())
                }
                Result(a)
            }
            (Const(a), Result(mut b)) => {
                for b in b.iter_mut() {
                    *b = f(a.clone(), b.clone())
                }
                Result(b)
            }
            (Result(mut a), Col(b)) => {
                for (a, b) in a.iter_mut().zip(b.iter()) {
                    *a = f(a.clone(), b.clone())
                }
                Result(a)
            }
            (Col(a), Result(mut b)) => {
                for (a, b) in a.iter().zip(b.iter_mut()) {
                    *b = f(a.clone(), b.clone())
                }
                Result(b)
            }
            (Result(mut a), Result(b)) => {
                for (a, b) in a.iter_mut().zip(b.into_iter()) {
                    *a = f(a.clone(), b)
                }
                Result(a)
            }
        }
    }

    pub fn unwrap(self) -> Vec<F>
    where
        F: Clone,
    {
        match self {
            EvalLeaf::Col(res) => res.to_vec(),
            EvalLeaf::Result(res) => res,
            EvalLeaf::Const(_) => panic!("Attempted to unwrap a constant"),
        }
    }
}
