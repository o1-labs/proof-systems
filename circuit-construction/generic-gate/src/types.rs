use std::collections::HashMap;

use proc_macro::{Ident, Literal};

use crate::constants::*;

pub(crate) struct Vars {
    lookup: HashMap<String, Var>,
}

impl Vars {
    pub fn new<I: Iterator<Item = String>>(names: I) -> Self {
        let mut lookup = HashMap::new();
        let mut assign = vec![Var::V1, Var::V2, Var::V3].into_iter();
        for name in names {
            let alias = assign.next().expect("too many free variables");
            lookup.insert(name, alias);
        }
        Self { lookup }
    }

    // resolve variable to name
    pub fn name(&self, v: Var) -> &str {
        if v == Var::Free {
            return NAME_FREE_VAR;
        }

        for (key, value) in self.lookup.iter() {
            if *value == v {
                return key;
            }
        }

        unreachable!("looked up: {:?}", v);
    }

    // resolve name to variable
    pub fn var(&self, name: &str) -> Option<Var> {
        self.lookup.get(name).copied()
    }
}

#[derive(Debug)]
pub(crate) struct Assignment {
    pub a: Option<Var>,
    pub b: Option<Var>,
    pub c: Option<Var>,
}

impl Assignment {
    pub fn lookup(&self, v: Var) -> C {
        let v = Some(v);

        if v == self.a {
            C::A
        } else if v == self.b {
            C::B
        } else if v == self.c {
            C::C
        } else {
            unreachable!("unassigned: {:?}", v)
        }
    }

    pub fn columns(&self) -> Vec<Var> {
        let mut columns = Vec::new();
        self.a.map(|a| columns.push(a));
        self.b.map(|b| columns.push(b));
        self.c.map(|c| columns.push(c));
        columns
    }
}

#[derive(Debug, Copy, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub(crate) enum Var {
    Free,
    V1,
    V2,
    V3,
}

#[derive(Debug)]
pub(crate) enum Const {
    Literal(Literal),
    Ident(Ident),
}

#[derive(Debug)]
pub(crate) enum Expr {
    Op(Operator, Box<Expr>, Box<Expr>),
    Var(Var),
    Const(Const),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Operator {
    Mul,
    Add,
    Sub,
}

#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub(crate) enum C {
    A,
    B,
    C,
    AB,
    CST,
}

impl C {
    pub const COLUMNS: [Self; 5] = [Self::A, Self::B, Self::C, Self::AB, Self::CST];
}

#[derive(Debug)]
pub(crate) struct Coeff {
    coeff: Vec<C>,
}

impl From<Vec<C>> for Coeff {
    fn from(coeff: Vec<C>) -> Self {
        assert!(coeff.len() >= 1);
        assert!(coeff.len() <= 5);
        Coeff { coeff }
    }
}

impl Coeff {
    pub fn index(&self, t: C) -> Option<usize> {
        self.coeff.iter().copied().position(|v| v == t)
    }

    pub fn a(&self) -> Option<usize> {
        self.index(C::A)
    }

    pub fn b(&self) -> Option<usize> {
        self.index(C::B)
    }

    pub fn c(&self) -> Option<usize> {
        self.index(C::C)
    }

    pub fn cst(&self) -> Option<usize> {
        self.index(C::CST)
    }

    pub fn ab(&self) -> Option<usize> {
        self.index(C::AB)
    }
}
