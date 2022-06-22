use proc_macro::{Delimiter, Group, TokenStream, TokenTree};

use crate::types::{Const, Expr, Operator, Var, Vars};

const EQ: char = '=';
const FREE_VAR: char = '?';

type ParseError = String;

fn parse_list(stream: TokenStream) -> Result<(Vec<TokenTree>, Vec<char>), ParseError> {
    let mut seps = vec![];
    let mut terms: Vec<TokenTree> = vec![];
    let mut stream = stream.into_iter();

    // parse non-empty list
    terms.push(token(&mut stream)?);
    while let Ok(sep) = punct(&mut stream) {
        seps.push(sep);
        terms.push(token(&mut stream)?);
    }

    Ok((terms, seps))
}

fn token<I: Iterator<Item = TokenTree>>(stream: &mut I) -> Result<TokenTree, ParseError> {
    match stream.next() {
        Some(t) => Ok(t),
        None => Err("expected token".to_owned()),
    }
}

fn punct<I: Iterator<Item = TokenTree>>(stream: &mut I) -> Result<char, ParseError> {
    match token(stream)? {
        TokenTree::Punct(punct) => Ok(punct.as_char()),
        _ => Err("expected a char".to_owned()),
    }
}

pub fn group<I: Iterator<Item = TokenTree>>(stream: &mut I) -> Result<Group, ParseError> {
    match token(stream)? {
        TokenTree::Group(group) => Ok(group),
        _ => Err("expected a group".to_owned()),
    }
}

pub fn seperator<I: Iterator<Item = TokenTree>>(
    stream: &mut I,
    sep: char,
) -> Result<(), ParseError> {
    match punct(stream) {
        Ok(found_sep) => {
            if found_sep == sep {
                Ok(())
            } else {
                Err("invalid seperator".to_owned())
            }
        }
        _ => Err("invalid/missing seperator".to_owned()),
    }
}

impl Var {
    fn parse(vars: &Vars, v: TokenTree) -> Result<Self, ParseError> {
        match v {
            TokenTree::Punct(punct) => match punct.as_char() {
                FREE_VAR => Ok(Var::Free),
                _ => Err(format!("punct used as var, but not {FREE_VAR}")),
            },
            TokenTree::Ident(ident) => match vars.var(&ident.to_string()) {
                Some(var) => Ok(var),
                None => Err(format!("variable {ident} not in witness tuple")),
            },
            _ => Err(format!("invalid variable {:?}", v)),
        }
    }
}

impl Operator {
    pub fn parse(o: TokenTree) -> Result<Operator, ParseError> {
        match o {
            TokenTree::Punct(op) => match op.as_char() {
                '*' => Ok(Operator::Mul),
                '+' => Ok(Operator::Add),
                '-' => Ok(Operator::Sub),
                _ => Err(format!("unexpected operator {}", op)),
            },
            _ => Err(format!("operator must be punct")),
        }
    }
}

// A list of <expr> (op) <expr> (op) ... (op) <expr>
struct ExprList {
    ops: Vec<Operator>,
    exprs: Vec<Expr>,
}

impl ExprList {
    fn parse(vars: &Vars, stream: TokenStream) -> Result<Self, ParseError> {
        let mut ops: Vec<Operator> = vec![];
        let mut exprs: Vec<Expr> = vec![];

        for (i, token) in stream.clone().into_iter().enumerate() {
            if i % 2 == 0 {
                exprs.push(Expr::parse(vars, token)?)
            } else {
                ops.push(Operator::parse(token)?)
            }
        }

        assert_eq!(
            ops.len() + 1,
            exprs.len(),
            "number of expr does not match number of terms: {:?}",
            stream
        );

        Ok(ExprList { ops, exprs })
    }

    fn to_expr(self) -> Expr {
        //
        let prec = vec![
            Operator::Mul, // binds tightest
            Operator::Add,
            Operator::Sub,
        ];

        let mut ops = self.ops;
        let mut exprs = self.exprs;

        // repeatedly coalesce terms
        // this is not very efficient, however the formulas are VERY SMALL.
        for op in prec {
            // coalesce one application of op at a time
            'coalesce: loop {
                assert_eq!(exprs.len() - 1, ops.len());
                for i in 0..ops.len() {
                    if ops[i] == op {
                        ops.remove(i);
                        let t1 = exprs.remove(i);
                        let t2 = exprs.remove(i);
                        exprs.insert(i, Expr::Op(op, Box::new(t1), Box::new(t2)));
                        continue 'coalesce;
                    }
                }
                break;
            }
        }

        // there should be exactly one expr left
        assert_eq!(exprs.len(), 1, "no/multiple expr left");
        assert_eq!(ops.len(), 0);
        exprs.pop().unwrap()
    }
}

impl Const {
    fn parse(_vars: &Vars, c: TokenTree) -> Result<Const, ParseError> {
        match c {
            TokenTree::Ident(ident) => Ok(Const::Ident(ident)),
            TokenTree::Literal(literal) => Ok(Const::Literal(literal)),
            _ => Err("invalid constant".to_owned()),
        }
    }
}

impl Expr {
    pub fn parse(vars: &Vars, e: TokenTree) -> Result<Expr, ParseError> {
        match e {
            TokenTree::Group(sub) => {
                assert_eq!(sub.delimiter(), Delimiter::Parenthesis);
                let list = ExprList::parse(vars, sub.stream())?;
                Ok(list.to_expr())
            }
            // could be constant or variable
            TokenTree::Ident(_) | TokenTree::Punct(_) => {
                if let Ok(var) = Var::parse(vars, e.clone()) {
                    Ok(Expr::Var(var))
                } else {
                    let constant = Const::parse(vars, e)?;
                    Ok(Expr::Const(constant))
                }
            }
            // must be constant
            TokenTree::Literal(_) => {
                let constant = Const::parse(vars, e)?;
                Ok(Expr::Const(constant))
            }
        }
    }

    pub fn parse_top(vars: &Vars, expr: Group) -> Result<Expr, ParseError> {
        let tokens: Vec<TokenTree> = expr.stream().into_iter().collect();

        let mut splits: Vec<&[TokenTree]> = vec![];

        // find ==
        let mut j = 0;
        for (i, token) in tokens.iter().enumerate() {
            if let TokenTree::Punct(punct) = token {
                if punct.as_char() == EQ {
                    splits.push(&tokens[j..i]);
                    j = i + 1;
                }
            }
        }

        splits.push(&tokens[j..]);

        assert_eq!(splits.len(), 2, "= not found {:?}", tokens);

        // parse left/right side

        let left =
            ExprList::parse(vars, TokenStream::from_iter(splits[0].iter().cloned()))?.to_expr();

        let right =
            ExprList::parse(vars, TokenStream::from_iter(splits[1].iter().cloned()))?.to_expr();

        // subtract right from left
        return Ok(Expr::Op(Operator::Sub, Box::new(left), Box::new(right)));
    }
}

impl Vars {
    pub fn parse(list: TokenTree) -> Self {
        match list {
            TokenTree::Group(group) => {
                // split list on ,
                let (vars, sep) =
                    parse_list(group.stream()).expect("variables must be seperated by ,");
                assert!(sep.into_iter().all(|c| c == ','));

                // assign the names to V1, V2, V3
                let names = vars.into_iter().map(|v| match v {
                    TokenTree::Ident(ident) => ident.to_string(),
                    _ => panic!("variables must be identifiers, not {:?}", v),
                });

                Vars::new(names)
            }
            _ => panic!("variables must be a tuple"),
        }
    }
}
