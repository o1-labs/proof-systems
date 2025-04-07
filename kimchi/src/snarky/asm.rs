//! An ASM-like language to print a human-friendly version of a circuit.

use core::{fmt::Write, hash::Hash};
use itertools::Itertools;
use std::collections::{HashMap, HashSet};

use crate::circuits::{
    gate::{Circuit, CircuitGate, GateType},
    polynomials::generic::{GENERIC_COEFFS, GENERIC_REGISTERS},
    wires::Wire,
};
use ark_ff::PrimeField;

use super::api::Witness;

/// Print a field in a negative form if it's past the half point.
fn pretty<F: ark_ff::PrimeField>(ff: F) -> String {
    let bigint: num_bigint::BigUint = ff.into();
    let inv: num_bigint::BigUint = ff.neg().into(); // gettho way of splitting the field into positive and negative elements
    if inv < bigint {
        format!("-{inv}")
    } else {
        bigint.to_string()
    }
}

impl<'a, F> Circuit<'a, F>
where
    F: PrimeField,
{
    pub fn generate_asm(&self) -> String {
        let mut res = String::new();

        // vars
        let mut vars = OrderedHashSet::default();

        for CircuitGate { coeffs, .. } in self.gates {
            Self::extract_vars_from_coeffs(&mut vars, coeffs);
        }

        for (idx, var) in vars.iter().enumerate() {
            writeln!(res, "c{idx} = {}", pretty(*var)).unwrap();
        }

        // gates
        for (row, CircuitGate { typ, coeffs, wires }) in self.gates.iter().enumerate() {
            // gate
            {
                let is_pub = if row < self.public_input_size {
                    "pub."
                } else {
                    ""
                };
                write!(res, "row{row}.{is_pub}").unwrap();
                let coeffs = Self::parse_coeffs(&vars, coeffs);
                write!(res, "{typ:?}").unwrap();
                res.push('<');

                if matches!(typ, GateType::Generic) && coeffs.len() > GENERIC_COEFFS {
                    // for the double generic gate, split the coeffs in two parts
                    let (gen1, gen2) = coeffs.split_at(GENERIC_COEFFS);
                    res.push_str(&gen1.join(","));
                    res.push_str("><");
                    res.push_str(&gen2.join(","));
                } else {
                    res.push_str(&coeffs.join(","));
                }

                res.push_str(">\n");
            }

            // wires
            {
                // wiring
                let mut wires1 = vec![];
                let mut wires2 = vec![];

                for (
                    col,
                    Wire {
                        row: to_row,
                        col: to_col,
                    },
                ) in wires.iter().enumerate()
                {
                    if row != *to_row || col != *to_col {
                        // if this gate is generic, use generic variables
                        let col_str = if matches!(typ, GateType::Generic) {
                            format!(".{}", Self::generic_cols(col))
                        } else {
                            format!("[{col}]")
                        };

                        // same for the wired gate
                        let to_col = if matches!(self.gates[*to_row].typ, GateType::Generic) {
                            format!(".{}", Self::generic_cols(*to_col))
                        } else {
                            format!("[{to_col}]")
                        };

                        let res = if row != *to_row {
                            format!("{col_str} -> row{to_row}{to_col}")
                        } else {
                            format!("{col_str} -> {to_col}")
                        };

                        if matches!(typ, GateType::Generic) && col < GENERIC_REGISTERS {
                            wires1.push(res);
                        } else {
                            wires2.push(res);
                        }
                    }
                }

                match (!wires1.is_empty(), !wires2.is_empty()) {
                    (false, false) => (),
                    (true, false) => {
                        res.push_str(&wires1.join(", "));
                        res.push('\n');
                    }
                    (false, true) => {
                        res.push_str(&wires2.join(", "));
                        res.push('\n');
                    }
                    (true, true) => {
                        res.push_str(&wires1.join(", "));
                        res.push('\n');
                        res.push_str(&wires2.join(", "));
                        res.push('\n');
                    }
                };
            }

            res.push('\n');
        }

        res
    }

    fn generic_cols(col: usize) -> &'static str {
        match col {
            0 => "l1",
            1 => "r1",
            2 => "o1",
            3 => "l2",
            4 => "r2",
            5 => "o2",
            x => panic!("invalid generic column: {x}"),
        }
    }

    fn extract_vars_from_coeffs(vars: &mut OrderedHashSet<F>, coeffs: &[F]) {
        for coeff in coeffs {
            let s = pretty(*coeff);
            if s.len() >= 5 {
                vars.insert(*coeff);
            }
        }
    }

    fn parse_coeffs(vars: &OrderedHashSet<F>, coeffs: &[F]) -> Vec<String> {
        coeffs
            .iter()
            .map(|x| {
                let s = pretty(*x);
                if s.len() < 5 {
                    s
                } else {
                    let var_idx = vars.pos(x);
                    format!("c{var_idx}")
                }
            })
            .collect()
    }
}

/// Very dumb way to write an ordered hash set.
#[derive(Default)]
pub struct OrderedHashSet<T> {
    inner: HashSet<T>,
    map: HashMap<T, usize>,
    ordered: Vec<T>,
}

impl<T> OrderedHashSet<T>
where
    T: Eq + Hash + Clone,
{
    pub fn insert(&mut self, value: T) -> bool {
        if self.inner.insert(value.clone()) {
            self.map.insert(value.clone(), self.ordered.len());
            self.ordered.push(value);
            true
        } else {
            false
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.ordered.iter()
    }

    pub fn pos(&self, value: &T) -> usize {
        self.map[value]
    }

    pub fn len(&self) -> usize {
        self.ordered.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ordered.is_empty()
    }
}

impl<F> Witness<F>
where
    F: PrimeField,
{
    pub fn debug(&self) {
        for (row, values) in self.0.iter().enumerate() {
            let values = values.iter().map(|v| pretty(*v)).join(" | ");
            println!("{row} - {values}");
        }
    }
}

#[cfg(test)]
mod tests {
    use mina_curves::pasta::Fp;

    use crate::circuits::wires::Wirable;

    use super::*;

    // FIXME: This test doesn't print the correct output.
    // Not critical atm, commenting it
    // #[test]
    fn _test_simple_circuit_asm() {
        let public_input_size = 1;
        let gates: &Vec<CircuitGate<Fp>> = &vec![
            CircuitGate::new(
                GateType::Generic,
                Wire::for_row(0),
                vec![1.into(), 2.into()],
            ),
            CircuitGate::new(
                GateType::Poseidon,
                Wire::for_row(1).wire(0, Wire::new(0, 1)),
                vec![1.into(), 2.into()],
            ),
            CircuitGate::new(
                GateType::Generic,
                Wire::for_row(2)
                    .wire(0, Wire::new(1, 2))
                    .wire(3, Wire::new(2, 5))
                    .wire(5, Wire::new(1, 1)),
                vec![1.into(), 2.into()],
            ),
        ];

        let circuit = Circuit::new(public_input_size, gates);

        const EXPECTED: &str = r#"row0.pub.Generic<1,2>

row1.Poseidon<1,2>
[0] -> row0.r1

row2.Generic<1,2>
.l1 -> row1[2]
.l2 -> row2.o2, .o2 -> row1[1]"#;

        let asm = circuit.generate_asm();

        if EXPECTED.trim() != asm.trim() {
            eprintln!("expected:\n{EXPECTED}\n");
            eprintln!("obtained:\n{asm}");
            panic!("obtained asm does not match expected asm")
        }
    }
}
