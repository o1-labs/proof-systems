#[derive(Clone, Debug)]
pub enum EvalLeaf<'a, F> {
    Const(F),
    Col(&'a Vec<F>),
    Result(Vec<F>),
}

impl<'a, F: std::fmt::Display> std::fmt::Display for EvalLeaf<'a, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let vec = match self {
            EvalLeaf::Const(c) => {
                write!(f, "Const: {}", c)?;
                return Ok(());
            }
            EvalLeaf::Col(a) => a,
            EvalLeaf::Result(a) => a,
        };
        writeln!(f, "[")?;
        for e in vec.iter() {
            writeln!(f, "{e}")?;
        }
        write!(f, "]")?;
        Ok(())
    }
}

impl<'a, F: std::ops::Add<Output = F> + Clone> std::ops::Add for EvalLeaf<'a, F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self::bin_op(|a, b| a + b, self, rhs)
    }
}

impl<'a, F: std::ops::Sub<Output = F> + Clone> std::ops::Sub for EvalLeaf<'a, F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self::bin_op(|a, b| a - b, self, rhs)
    }
}

impl<'a, F: std::ops::Mul<Output = F> + Clone> std::ops::Mul for EvalLeaf<'a, F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self::bin_op(|a, b| a * b, self, rhs)
    }
}

impl<'a, F: std::ops::Mul<Output = F> + Clone> std::ops::Mul<F> for EvalLeaf<'a, F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self {
        self * Self::Const(rhs)
    }
}

impl<'a, F: Clone> EvalLeaf<'a, F> {
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
