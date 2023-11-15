use crate::folding::expressions::{extract_terms, FoldingColumn, FoldingExp};

#[ignore]
#[test]
fn test_term_separation() {
    let t1 = FoldingExp::<i32>::Mul(
        Box::new(FoldingExp::Add(
            Box::new(FoldingExp::Cell(FoldingColumn::Witness(0))),
            Box::new(FoldingExp::Cell(FoldingColumn::Witness(1))),
        )),
        Box::new(FoldingExp::Add(
            Box::new(FoldingExp::Cell(FoldingColumn::Witness(2))),
            Box::new(FoldingExp::Cell(FoldingColumn::Witness(3))),
        )),
    );
    let t2 = FoldingExp::Sub(
        Box::new(FoldingExp::Square(Box::new(FoldingExp::Cell(
            FoldingColumn::Witness(1),
        )))),
        Box::new(FoldingExp::Add(
            Box::new(FoldingExp::Cell(FoldingColumn::Witness(2))),
            Box::new(FoldingExp::Constant(5)),
        )),
    );
    let test_exp = FoldingExp::Add(Box::new(t1), Box::new(t2));
    // let test_exp = t1;
    let mut terms = vec![];
    println!("{:#?}", test_exp);
    extract_terms(test_exp, &mut terms, &|t| t);
    println!("{:#?}", terms);
}
