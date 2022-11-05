//! An ASM-like language to print a human-friendly version of a circuit.

use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::hash::Hash;

use crate::circuits::gate::{Circuit, CircuitGate, GateType};
use crate::circuits::polynomials::generic::{GENERIC_COEFFS, GENERIC_REGISTERS};
use crate::circuits::wires::Wire;
use ark_ff::PrimeField;

/// Print a field in a negative form if it's past the half point.
fn pretty<F: ark_ff::PrimeField>(ff: F) -> String {
    let bigint: num_bigint::BigUint = ff.into();
    let inv: num_bigint::BigUint = ff.neg().into(); // gettho way of splitting the field into positive and negative elements
    if inv < bigint {
        format!("-{}", inv)
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
                write!(res, "row{row}.").unwrap();
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
                let mut wires_str = vec![];
                for (
                    col,
                    Wire {
                        row: to_row,
                        col: to_col,
                    },
                ) in wires.iter().enumerate()
                {
                    if row != *to_row || col != *to_col {
                        let col = if matches!(typ, GateType::Generic) {
                            format!(".{}", Self::generic_cols(col))
                        } else {
                            format!("[{col}]")
                        };

                        let to_col = if matches!(self.gates[*to_row].typ, GateType::Generic) {
                            format!(".{}", Self::generic_cols(*to_col))
                        } else {
                            format!("[{to_col}]")
                        };

                        wires_str.push(format!("{col} -> row{to_row}{to_col}"));
                    }
                }

                if !wires_str.is_empty() {
                    if matches!(typ, GateType::Generic) && wires_str.len() > GENERIC_REGISTERS {
                        let (wires1, wires2) = wires_str.split_at(GENERIC_REGISTERS);
                        res.push_str(&wires1.join(", "));
                        res.push('\n');
                        res.push_str(&wires2.join(", "));
                    } else {
                        res.push_str(&wires_str.join(", "));
                    }
                    res.push('\n');
                }
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

#[cfg(test)]
mod tests {
    use mina_curves::pasta::Fp;

    use crate::circuits::wires::Wirable;

    use super::*;

    #[test]
    fn test_simple_circuit_asm() {
        let public_input_size = 0;
        let gates: &Vec<CircuitGate<Fp>> = &vec![
            CircuitGate {
                typ: GateType::Generic,
                wires: Wire::for_row(0),
                coeffs: vec![1.into(), 2.into()],
            },
            CircuitGate {
                typ: GateType::Poseidon,
                wires: Wire::for_row(1).wire(0, Wire::new(0, 1)),
                coeffs: vec![1.into(), 2.into()],
            },
            CircuitGate {
                typ: GateType::Generic,
                wires: Wire::for_row(2).wire(5, Wire::new(1, 1)),
                coeffs: vec![1.into(), 2.into()],
            },
        ];

        let circuit = Circuit::new(public_input_size, gates);

        const EXPECTED: &str = r#"row0.Generic<1,2>

row1.Poseidon<1,2>
[0] -> row0.r1

row2.Generic<1,2>
.o2 -> row1[1]"#;

        let asm = circuit.generate_asm();

        if EXPECTED.trim() != asm.trim() {
            eprintln!("expected:\n{EXPECTED}\n");
            eprintln!("obtained:\n{asm}");
            panic!("obtained asm does not match expected asm")
        }
    }
}
