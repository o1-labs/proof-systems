use kimchi::{
    circuits::{
        berkeley_columns::{BerkeleyChallengeTerm, Column},
        constraints::FeatureFlags,
        expr::{ConstantTerm, FeatureFlag, Linearization, PolishToken},
        gate::CurrOrNext,
        lookup::lookups::{LookupFeatures, LookupPatterns},
    },
    linearization::{constraints_expr, linearization_columns},
};

/// The RPN tokens of a single linearization term, in OCaml evaluation order.
type Tokens<F> = Vec<PolishToken<F, Column, BerkeleyChallengeTerm>>;

/// OCaml-facing mirror of [`ConstantTerm`]. Differs from the kimchi type only
/// in the shape needed to cross the FFI: a tuple `Mds` variant (`ocaml_gen`
/// rejects named-field variants) and the field literal carried as the hex
/// string the OCaml `Env.field` already parses (so the token type stays
/// field-agnostic — the `fp` and `fq` linearizations share it).
#[derive(Clone, Debug, ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Enum)]
pub enum CamlConstantTerm {
    EndoCoefficient,
    Mds(ocaml::Int, ocaml::Int),
    Literal(String),
}

/// OCaml-facing mirror of [`PolishToken`] for the Berkeley column/challenge
/// instantiation. Differs from the kimchi type only where `ocaml_gen` requires
/// it, keeping the variants shallow: [`CamlConstantTerm`] in place of
/// [`ConstantTerm`], `Pow`/`Load`/skip counts as OCaml integers rather than
/// `u64`, and the `Variable`/`RowOffset` records flattened into their fields.
#[derive(Clone, Debug, ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Enum)]
pub enum CamlPolishToken {
    Constant(CamlConstantTerm),
    Challenge(BerkeleyChallengeTerm),
    Cell(Column, CurrOrNext),
    Dup,
    Pow(ocaml::Int),
    Add,
    Mul,
    Sub,
    VanishesOnZeroKnowledgeAndPreviousRows,
    UnnormalizedLagrangeBasis(bool, ocaml::Int),
    Store,
    Load(ocaml::Int),
    SkipIf(FeatureFlag, ocaml::Int),
    SkipIfNot(FeatureFlag, ocaml::Int),
}

type CamlTokens = Vec<CamlPolishToken>;

impl<F: ark_ff::PrimeField> From<ConstantTerm<F>> for CamlConstantTerm
where
    num_bigint::BigUint: From<F::BigInt>,
{
    fn from(c: ConstantTerm<F>) -> Self {
        match c {
            ConstantTerm::EndoCoefficient => CamlConstantTerm::EndoCoefficient,
            ConstantTerm::Mds { row, col } => {
                CamlConstantTerm::Mds(row as ocaml::Int, col as ocaml::Int)
            }
            // Same hex rendering the generated code used for `field("0x..")`,
            // so `Env.field` parses an identical constant.
            ConstantTerm::Literal(x) => CamlConstantTerm::Literal(format!(
                "{:#066X}",
                Into::<num_bigint::BigUint>::into(x.into_bigint())
            )),
        }
    }
}

impl<F: ark_ff::PrimeField> From<PolishToken<F, Column, BerkeleyChallengeTerm>> for CamlPolishToken
where
    num_bigint::BigUint: From<F::BigInt>,
{
    fn from(t: PolishToken<F, Column, BerkeleyChallengeTerm>) -> Self {
        use PolishToken::*;
        match t {
            Constant(c) => CamlPolishToken::Constant(c.into()),
            Challenge(c) => CamlPolishToken::Challenge(c),
            Cell(v) => CamlPolishToken::Cell(v.col, v.row),
            Dup => CamlPolishToken::Dup,
            Pow(n) => CamlPolishToken::Pow(n as ocaml::Int),
            Add => CamlPolishToken::Add,
            Mul => CamlPolishToken::Mul,
            Sub => CamlPolishToken::Sub,
            VanishesOnZeroKnowledgeAndPreviousRows => {
                CamlPolishToken::VanishesOnZeroKnowledgeAndPreviousRows
            }
            UnnormalizedLagrangeBasis(i) => {
                CamlPolishToken::UnnormalizedLagrangeBasis(i.zk_rows, i.offset as ocaml::Int)
            }
            Store => CamlPolishToken::Store,
            Load(i) => CamlPolishToken::Load(i as ocaml::Int),
            SkipIf(f, n) => CamlPolishToken::SkipIf(f, n as ocaml::Int),
            SkipIfNot(f, n) => CamlPolishToken::SkipIfNot(f, n as ocaml::Int),
        }
    }
}

fn caml_tokens<F: ark_ff::PrimeField>(tokens: Tokens<F>) -> CamlTokens
where
    num_bigint::BigUint: From<F::BigInt>,
{
    tokens.into_iter().map(CamlPolishToken::from).collect()
}

fn features(uses_custom_gates: bool) -> Option<FeatureFlags> {
    if uses_custom_gates {
        None
    } else {
        Some(FeatureFlags {
            range_check0: false,
            range_check1: false,
            foreign_field_add: false,
            foreign_field_mul: false,
            xor: false,
            rot: false,
            lookup_features: LookupFeatures {
                patterns: LookupPatterns {
                    xor: false,
                    lookup: false,
                    range_check: false,
                    foreign_field_mul: false,
                },
                joint_lookup_used: false,
                uses_runtime_tables: false,
            },
        })
    }
}

/// Converts the linearization of the kimchi circuit polynomial into a printable string.
pub fn linearization_strings<F: ark_ff::PrimeField>(
    uses_custom_gates: bool,
) -> (String, Vec<(String, String)>)
where
    num_bigint::BigUint: From<F::BigInt>,
{
    let features = features(uses_custom_gates);
    let evaluated_cols = linearization_columns::<F>(features.as_ref());
    let (linearization, _powers_of_alpha) = constraints_expr::<F>(features.as_ref(), true);

    let Linearization {
        constant_term,
        mut index_terms,
    } = linearization.linearize(evaluated_cols).unwrap();

    // HashMap deliberately uses an unstable order; here we sort to ensure that
    // the output is consistent when printing.
    index_terms.sort_by_key(|(x, _)| *x);

    let constant = constant_term.ocaml_str();
    let other_terms = index_terms
        .iter()
        .map(|(col, expr)| (format!("{:?}", col), expr.ocaml_str()))
        .collect();

    (constant, other_terms)
}

#[ocaml::func]
pub fn fp_linearization_strings() -> (String, Vec<(String, String)>) {
    linearization_strings::<mina_curves::pasta::Fp>(true)
}

#[ocaml::func]
pub fn fq_linearization_strings() -> (String, Vec<(String, String)>) {
    linearization_strings::<mina_curves::pasta::Fq>(false)
}

/// The linearization of the kimchi circuit polynomial as RPN token streams, in
/// OCaml evaluation order (see [`PolishToken`] / `Expr::to_ocaml_ordered_polish`).
/// The constant term comes first, followed by the index terms keyed by their
/// column (rendered as the column's `Debug` string, matching
/// [`linearization_strings`]).
pub fn linearization_tokens<F: ark_ff::PrimeField>(
    uses_custom_gates: bool,
) -> (Tokens<F>, Vec<(String, Tokens<F>)>) {
    let features = features(uses_custom_gates);
    let evaluated_cols = linearization_columns::<F>(features.as_ref());
    let (linearization, _powers_of_alpha) = constraints_expr::<F>(features.as_ref(), true);

    let Linearization {
        constant_term,
        mut index_terms,
    } = linearization.linearize(evaluated_cols).unwrap();

    // HashMap deliberately uses an unstable order; here we sort to ensure that
    // the output is consistent.
    index_terms.sort_by_key(|(x, _)| *x);

    let constant = constant_term.to_ocaml_ordered_polish();
    let other_terms = index_terms
        .iter()
        .map(|(col, expr)| (format!("{:?}", col), expr.to_ocaml_ordered_polish()))
        .collect();

    (constant, other_terms)
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn fp_linearization_tokens() -> (CamlTokens, Vec<(String, CamlTokens)>) {
    let (constant, other_terms) = linearization_tokens::<mina_curves::pasta::Fp>(true);
    (
        caml_tokens(constant),
        other_terms
            .into_iter()
            .map(|(col, tokens)| (col, caml_tokens(tokens)))
            .collect(),
    )
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn fq_linearization_tokens() -> (CamlTokens, Vec<(String, CamlTokens)>) {
    let (constant, other_terms) = linearization_tokens::<mina_curves::pasta::Fq>(false);
    (
        caml_tokens(constant),
        other_terms
            .into_iter()
            .map(|(col, tokens)| (col, caml_tokens(tokens)))
            .collect(),
    )
}
