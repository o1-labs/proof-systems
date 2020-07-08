/*****************************************************************************************************************

This source file implements Weierstrass curve variable base scalar multiplication custom Plonk constraints.

*****************************************************************************************************************/

use algebra::Field;
use crate::gate::{CircuitGate, GateType};

impl<F: Field> CircuitGate<F>
{
    pub fn create_vbmul
    (
        l1: (usize, usize),
        r1: (usize, usize),
        o1: (usize, usize),
        l2: (usize, usize),
        r2: (usize, usize),
        o2: (usize, usize),
        l3: (usize, usize),
        r3: (usize, usize),
        o3: (usize, usize),
    ) -> Vec<Self>
    {
        vec![
            CircuitGate
            {
                typ: GateType::Vbmul1,
                l: l1,
                r: r1,
                o: o1,
                c: vec![]
            },
            CircuitGate
            {
                typ: GateType::Vbmul2,
                l: l2,
                r: r2,
                o: o2,
                c: vec![]
            },
            CircuitGate
            {
                typ: GateType::Vbmul3,
                l: l3,
                r: r3,
                o: o3,
                c: vec![]
            },
        ]
    }

    pub fn verify_vbmul1(&self, _witness: &Vec<F>, _next: &Self) -> bool
    {
        false
    }

    pub fn verify_vbmul2(&self, _witness: &Vec<F>, _next: &Self) -> bool
    {
        false
    }

    pub fn verify_vbmul3(&self, _witness: &Vec<F>, _next: &Self) -> bool
    {
        false
    }

    pub fn vbmul1(&self) -> F {if self.typ == GateType::Vbmul1 {F::one()} else {F::zero()}}
    pub fn vbmul2(&self) -> F {if self.typ == GateType::Vbmul2 {F::one()} else {F::zero()}}
    pub fn vbmul3(&self) -> F {if self.typ == GateType::Vbmul3 {F::one()} else {F::zero()}}
}
