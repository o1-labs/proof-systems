//! The Berkeley linearization as OCaml-ordered RPN token streams (see
//! [`PolishToken`] / `Expr::to_ocaml_ordered_polish`), plus an encoding of
//! those streams into the js_of_ocaml value representation for the wasm and
//! napi FFI crates.
//!
//! The native FFI (`kimchi-stubs`) hands the tokens to OCaml as real variant
//! values via `ocaml-rs`; that machinery needs the OCaml C runtime and so
//! cannot exist under js_of_ocaml, where OCaml values are plain JavaScript
//! values. The wasm/napi crates instead return the streams as one JSON string
//! produced here, in which every variant already carries its js_of_ocaml
//! encoding: a constant constructor is its index (among the constant
//! constructors only), and a payload constructor is an array
//! `[tag, arg, ...]` with the tag counted among the payload constructors
//! only, both in declaration order of the corresponding OCaml type. The JS
//! side (`kimchi_bindings/js/bindings/linearization.js`) only converts
//! strings to OCaml strings and adds array/tuple framing.
//!
//! The tag values below are dictated by the generated OCaml declarations in
//! `src/lib/crypto/kimchi_bindings/stubs/kimchi_types.ml` (`polish_token`,
//! `constant_term`, `challenge_term`, `column`, `curr_or_next`, `gate_type`,
//! `lookup_pattern`, `feature_flag`); any change there must be mirrored here.

use crate::{
    circuits::{
        berkeley_columns::{BerkeleyChallengeTerm, Column},
        constraints::FeatureFlags,
        expr::{ConstantTerm, FeatureFlag, Linearization, PolishToken},
        gate::{CurrOrNext, GateType},
        lookup::lookups::{LookupFeatures, LookupPattern, LookupPatterns},
    },
    linearization::{constraints_expr, linearization_columns},
};
use serde_json::{json, Value};

/// The RPN tokens of a single linearization term, in OCaml evaluation order.
pub type Tokens<F> = Vec<PolishToken<F, Column, BerkeleyChallengeTerm>>;

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

/// The linearization of the kimchi circuit polynomial as RPN token streams, in
/// OCaml evaluation order. The constant term comes first, followed by the
/// index terms keyed by their column (rendered as the column's `Debug`
/// string). Mirrors `linearization_tokens` in `kimchi-stubs`.
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

// gate_type: all 14 constructors are constant.
fn gate_type_js(g: GateType) -> Value {
    json!(match g {
        GateType::Zero => 0,
        GateType::Generic => 1,
        GateType::Poseidon => 2,
        GateType::CompleteAdd => 3,
        GateType::VarBaseMul => 4,
        GateType::EndoMul => 5,
        GateType::EndoMulScalar => 6,
        GateType::Lookup => 7,
        GateType::RangeCheck0 => 8,
        GateType::RangeCheck1 => 9,
        GateType::ForeignFieldAdd => 10,
        GateType::ForeignFieldMul => 11,
        GateType::Xor16 => 12,
        GateType::Rot64 => 13,
    })
}

// lookup_pattern: all constant.
fn lookup_pattern_js(p: LookupPattern) -> Value {
    json!(match p {
        LookupPattern::Xor => 0,
        LookupPattern::Lookup => 1,
        LookupPattern::RangeCheck => 2,
        LookupPattern::ForeignFieldMul => 3,
    })
}

// column: constants Z | LookupAggreg | LookupTable | LookupRuntimeSelector
// | LookupRuntimeTable; payloads Witness | LookupSorted | LookupKindIndex
// | Index | Coefficient | Permutation.
fn column_js(c: &Column) -> Value {
    match c {
        Column::Z => json!(0),
        Column::LookupAggreg => json!(1),
        Column::LookupTable => json!(2),
        Column::LookupRuntimeSelector => json!(3),
        Column::LookupRuntimeTable => json!(4),
        Column::Witness(i) => json!([0, i]),
        Column::LookupSorted(i) => json!([1, i]),
        Column::LookupKindIndex(p) => json!([2, lookup_pattern_js(*p)]),
        Column::Index(g) => json!([3, gate_type_js(*g)]),
        Column::Coefficient(i) => json!([4, i]),
        Column::Permutation(i) => json!([5, i]),
    }
}

// challenge_term: all constant.
fn challenge_js(c: BerkeleyChallengeTerm) -> Value {
    json!(match c {
        BerkeleyChallengeTerm::Alpha => 0,
        BerkeleyChallengeTerm::Beta => 1,
        BerkeleyChallengeTerm::Gamma => 2,
        BerkeleyChallengeTerm::JointCombiner => 3,
    })
}

// feature_flag: constants RangeCheck0..RuntimeLookupTables; payloads
// LookupPattern | TableWidth | LookupsPerRow.
fn feature_flag_js(f: &FeatureFlag) -> Value {
    match f {
        FeatureFlag::RangeCheck0 => json!(0),
        FeatureFlag::RangeCheck1 => json!(1),
        FeatureFlag::ForeignFieldAdd => json!(2),
        FeatureFlag::ForeignFieldMul => json!(3),
        FeatureFlag::Xor => json!(4),
        FeatureFlag::Rot => json!(5),
        FeatureFlag::LookupTables => json!(6),
        FeatureFlag::RuntimeLookupTables => json!(7),
        FeatureFlag::LookupPattern(p) => json!([0, lookup_pattern_js(*p)]),
        FeatureFlag::TableWidth(w) => json!([1, w]),
        FeatureFlag::LookupsPerRow(n) => json!([2, n]),
    }
}

// constant_term: constant EndoCoefficient; payloads Mds | Literal. The field
// literal crosses as the same hex rendering `kimchi-stubs` uses, which the
// OCaml `Env.field` parses; this keeps the encoding field-agnostic.
fn constant_term_js<F: ark_ff::PrimeField>(c: &ConstantTerm<F>) -> Value
where
    num_bigint::BigUint: From<F::BigInt>,
{
    match c {
        ConstantTerm::EndoCoefficient => json!(0),
        ConstantTerm::Mds { row, col } => json!([0, row, col]),
        ConstantTerm::Literal(x) => json!([
            1,
            format!(
                "{:#066X}",
                Into::<num_bigint::BigUint>::into(x.into_bigint())
            )
        ]),
    }
}

// polish_token: constants Dup | Add | Mul | Sub
// | VanishesOnZeroKnowledgeAndPreviousRows | Store; payloads Constant
// | Challenge | Cell | Pow | UnnormalizedLagrangeBasis | Load | SkipIf
// | SkipIfNot. OCaml bools are 0/1.
fn token_js<F: ark_ff::PrimeField>(t: &PolishToken<F, Column, BerkeleyChallengeTerm>) -> Value
where
    num_bigint::BigUint: From<F::BigInt>,
{
    use PolishToken::*;
    match t {
        Dup => json!(0),
        Add => json!(1),
        Mul => json!(2),
        Sub => json!(3),
        VanishesOnZeroKnowledgeAndPreviousRows => json!(4),
        Store => json!(5),
        Constant(c) => json!([0, constant_term_js(c)]),
        Challenge(c) => json!([1, challenge_js(*c)]),
        Cell(v) => {
            let row = match v.row {
                CurrOrNext::Curr => 0,
                CurrOrNext::Next => 1,
            };
            json!([2, column_js(&v.col), row])
        }
        Pow(n) => json!([3, n]),
        UnnormalizedLagrangeBasis(i) => {
            json!([4, if i.zk_rows { 1 } else { 0 }, i.offset])
        }
        Load(i) => json!([5, i]),
        SkipIf(f, n) => json!([6, feature_flag_js(f), n]),
        SkipIfNot(f, n) => json!([7, feature_flag_js(f), n]),
    }
}

/// The result of [`linearization_tokens`] as one JSON string:
/// `[constant_tokens, [[column_name, tokens], ...]]`, with every token in the
/// js_of_ocaml encoding described in the module documentation.
pub fn linearization_tokens_ocaml_json<F: ark_ff::PrimeField>(uses_custom_gates: bool) -> String
where
    num_bigint::BigUint: From<F::BigInt>,
{
    let (constant, index_terms) = linearization_tokens::<F>(uses_custom_gates);
    let constant: Vec<Value> = constant.iter().map(token_js).collect();
    let index_terms: Vec<Value> = index_terms
        .iter()
        .map(|(name, tokens)| json!([name, tokens.iter().map(token_js).collect::<Vec<_>>()]))
        .collect();
    json!([constant, index_terms]).to_string()
}
