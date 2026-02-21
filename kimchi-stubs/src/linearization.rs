use kimchi::{
    circuits::{
        berkeley_columns::{BerkeleyChallengeTerm, Column},
        constraints::FeatureFlags,
        expr::{ConstantTerm, FeatureFlag, Linearization, PolishToken, RowOffset},
        gate::CurrOrNext,
        lookup::lookups::{LookupFeatures, LookupPattern, LookupPatterns},
    },
    linearization::{constraints_expr, linearization_columns},
};

/// Converts the linearization of the kimchi circuit polynomial into a printable string.
pub fn linearization_strings<F: ark_ff::PrimeField>(
    uses_custom_gates: bool,
) -> (String, Vec<(String, String)>)
where
    num_bigint::BigUint: From<F::BigInt>,
{
    let features = if uses_custom_gates {
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
    };
    let evaluated_cols = linearization_columns::<F>(features.as_ref());
    let (linearization, _powers_of_alpha) = constraints_expr::<F>(features.as_ref(), true);

    let Linearization {
        constant_term,
        mut index_terms,
    } = linearization.linearize(evaluated_cols).unwrap();

    // HashMap deliberately uses an unstable order; here we sort to ensure that
    // the output is consistent when printing.
    index_terms.sort_by(|(x, _), (y, _)| x.cmp(y));

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

// ---------------------------------------------------------------------------
// Token-stream codegen: to_polish() → OCaml array literal
// ---------------------------------------------------------------------------

fn format_lookup_pattern(p: &LookupPattern) -> &'static str {
    match p {
        LookupPattern::Xor => "Lookup_pattern.Xor",
        LookupPattern::Lookup => "Lookup_pattern.Lookup",
        LookupPattern::RangeCheck => "Lookup_pattern.RangeCheck",
        LookupPattern::ForeignFieldMul => "Lookup_pattern.ForeignFieldMul",
    }
}

fn format_feature_flag(flag: &FeatureFlag) -> String {
    match flag {
        FeatureFlag::RangeCheck0 => "Feature_flag.RangeCheck0".to_string(),
        FeatureFlag::RangeCheck1 => "Feature_flag.RangeCheck1".to_string(),
        FeatureFlag::ForeignFieldAdd => "Feature_flag.ForeignFieldAdd".to_string(),
        FeatureFlag::ForeignFieldMul => "Feature_flag.ForeignFieldMul".to_string(),
        FeatureFlag::Xor => "Feature_flag.Xor".to_string(),
        FeatureFlag::Rot => "Feature_flag.Rot".to_string(),
        FeatureFlag::LookupTables => "Feature_flag.LookupTables".to_string(),
        FeatureFlag::RuntimeLookupTables => "Feature_flag.RuntimeLookupTables".to_string(),
        FeatureFlag::LookupPattern(p) => {
            format!("Feature_flag.LookupPattern {}", format_lookup_pattern(p))
        }
        FeatureFlag::TableWidth(n) => format!("Feature_flag.TableWidth {}", n),
        FeatureFlag::LookupsPerRow(n) => format!("Feature_flag.LookupsPerRow {}", n),
    }
}

fn format_column(col: &Column) -> String {
    match col {
        Column::Witness(i) => format!("Witness {}", i),
        Column::Z => "Z".to_string(),
        Column::LookupSorted(i) => format!("LookupSorted {}", i),
        Column::LookupAggreg => "LookupAggreg".to_string(),
        Column::LookupTable => "LookupTable".to_string(),
        Column::LookupKindIndex(p) => {
            format!("LookupKindIndex {}", format_lookup_pattern(p))
        }
        Column::LookupRuntimeSelector => "LookupRuntimeSelector".to_string(),
        Column::LookupRuntimeTable => "LookupRuntimeTable".to_string(),
        Column::Index(gt) => format!("Index Gate_type.{:?}", gt),
        Column::Coefficient(i) => format!("Coefficient {}", i),
        Column::Permutation(i) => format!("Permutation {}", i),
    }
}

fn format_token<F: ark_ff::PrimeField>(
    token: &PolishToken<F, Column, BerkeleyChallengeTerm>,
) -> String
where
    num_bigint::BigUint: From<F::BigInt>,
{
    match token {
        PolishToken::Constant(ConstantTerm::EndoCoefficient) => {
            "Constant EndoCoefficient".to_string()
        }
        PolishToken::Constant(ConstantTerm::Mds { row, col }) => {
            format!("Constant (Mds ({}, {}))", row, col)
        }
        PolishToken::Constant(ConstantTerm::Literal(f)) => {
            let bigint: num_bigint::BigUint = (*f).into_bigint().into();
            format!("Constant (Literal \"0x{:X}\")", bigint)
        }
        PolishToken::Challenge(BerkeleyChallengeTerm::Alpha) => "Challenge Alpha".to_string(),
        PolishToken::Challenge(BerkeleyChallengeTerm::Beta) => "Challenge Beta".to_string(),
        PolishToken::Challenge(BerkeleyChallengeTerm::Gamma) => "Challenge Gamma".to_string(),
        PolishToken::Challenge(BerkeleyChallengeTerm::JointCombiner) => {
            "Challenge JointCombiner".to_string()
        }
        PolishToken::Cell(var) => {
            let col = format_column(&var.col);
            let row = match var.row {
                CurrOrNext::Curr => "Curr",
                CurrOrNext::Next => "Next",
            };
            format!("Cell ({}, {})", col, row)
        }
        PolishToken::Dup => "Dup".to_string(),
        PolishToken::Pow(n) => format!("Pow {}", n),
        PolishToken::Add => "Add".to_string(),
        PolishToken::Mul => "Mul".to_string(),
        PolishToken::Sub => "Sub".to_string(),
        PolishToken::VanishesOnZeroKnowledgeAndPreviousRows => {
            "VanishesOnZeroKnowledgeAndPreviousRows".to_string()
        }
        PolishToken::UnnormalizedLagrangeBasis(RowOffset { zk_rows, offset }) => {
            format!("UnnormalizedLagrangeBasis ({}, {})", zk_rows, offset)
        }
        PolishToken::Store => "Store".to_string(),
        PolishToken::Load(i) => format!("Load {}", i),
        PolishToken::SkipIf(flag, count) => {
            format!("SkipIf ({}, {})", format_feature_flag(flag), count)
        }
        PolishToken::SkipIfNot(flag, count) => {
            format!("SkipIfNot ({}, {})", format_feature_flag(flag), count)
        }
    }
}

fn format_tokens_as_ocaml_array<F: ark_ff::PrimeField>(
    tokens: &[PolishToken<F, Column, BerkeleyChallengeTerm>],
) -> String
where
    num_bigint::BigUint: From<F::BigInt>,
{
    let formatted: Vec<String> = tokens
        .iter()
        .map(|t| format!("    {}", format_token(t)))
        .collect();
    format!("[|\n{};\n  |]", formatted.join(";\n"))
}

/// Converts the linearization to compact polish token streams formatted as OCaml array literals.
pub fn linearization_token_strings<F: ark_ff::PrimeField>(
    uses_custom_gates: bool,
) -> (String, Vec<(String, String)>)
where
    num_bigint::BigUint: From<F::BigInt>,
{
    let features = if uses_custom_gates {
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
    };
    let evaluated_cols = linearization_columns::<F>(features.as_ref());
    let (linearization, _powers_of_alpha) = constraints_expr::<F>(features.as_ref(), true);

    let Linearization {
        constant_term,
        mut index_terms,
    } = linearization.linearize(evaluated_cols).unwrap();

    index_terms.sort_by(|(x, _), (y, _)| x.cmp(y));

    let constant = format_tokens_as_ocaml_array(&constant_term.to_polish());
    let other_terms = index_terms
        .iter()
        .map(|(col, expr)| {
            (
                format!("{:?}", col),
                format_tokens_as_ocaml_array(&expr.to_polish()),
            )
        })
        .collect();

    (constant, other_terms)
}

#[ocaml::func]
pub fn fp_linearization_token_strings() -> (String, Vec<(String, String)>) {
    linearization_token_strings::<mina_curves::pasta::Fp>(true)
}

#[ocaml::func]
pub fn fq_linearization_token_strings() -> (String, Vec<(String, String)>) {
    linearization_token_strings::<mina_curves::pasta::Fq>(false)
}
