/*****************************************************************************************************************

This source file implements group endomorphism optimised
variable base scalar multiplication custom Plonk constraints.

EVBSM gate constraints

    b1*(b1-1) = 0
    b2*(b2-1) = 0
    (xp - (1 + (endo - 1) * b2) * xt) * s1 = yp – (2*b1-1)*yt
    s1^2 - s2^2 = (1 + (endo - 1) * b2) * xt - xs
    (2*xp + (1 + (endo - 1) * b2) * xt – s1^2) * (s1 + s2) = 2*yp
    (xp – xs) * s2 = ys + yp

Permutation constraints

    -> b1(i)
    -> b2(i+1)
    -> xt(i) -> xt(i+2) -> … -> xt(255)
    -> yt(i) -> yt(i+2) -> … -> yt(255)
    -> xp(i)
    -> xp(i+2) -> xs(i) ->
    -> yp(i)
    -> yp(i+2) -> ys(i) ->
    xs(255) ->
    ys(255) ->

The constraints above are derived from the following EC Affine arithmetic equations:

    (xq - xp) * s1 = yq - yp
    s1 * s1 = xp + xq + x1
    (xp – x1) * s1 = y1 + yp

    (x1 – xp) * s2 = y1 – yp
    s2 * s2 = xp + x1 + xs
    (xp – xs) * s2 = ys + yp

    =>

    (xq - xp) * s1 = yq - yp
    s1^2 = xp + xq + x1
    (xp – x1) * (s1 + s2) = 2*yp
    s2^2 = xp + x1 + xs
    (xp – xs) * s2 = ys + yp

    =>

    (xq - xp) * s1 = yq - yp
    s1^2 - s2^2 = xq - xs
    (2*xp + xq – s1^2) * (s1 + s2) = 2*yp
    (xp – xs) * s2 = ys + yp

*****************************************************************************************************************/

use ark_ff::FftField;
use crate::gate::{CircuitGate, GateType};
use crate::{wires::{GateWires, COLUMNS}, constraints::ConstraintSystem};
use array_init::array_init;

impl<F: FftField> CircuitGate<F>
{
    pub fn create_endomul(row: usize, wires: GateWires) -> Self
    {
        CircuitGate
        {
            row,
            typ: GateType::Endomul,
            wires,
            c: vec![]
        }
    }

    pub fn verify_endomul(&self, witness: &[Vec<F>; COLUMNS], cs: &ConstraintSystem<F>) -> bool
    {
        let this: [F; COLUMNS] = array_init(|i| witness[i][self.row]);
        let next: [F; COLUMNS] = array_init(|i| witness[i][self.row+1]);
        let xq = (F::one() + &((cs.endo - &F::one()) * &next[4])) * &this[0];
        
        self.typ == GateType::Endomul
        &&
        // verify booleanity of the scalar bits
        this[4] == this[4].square()
        &&
        next[4] == next[4].square()
        &&
        // (xp - (1 + (endo - 1) * b2) * xt) * s1 = yp – (2*b1-1)*yt
        (next[2] - &xq) * &this[2] == next[3] - &(this[1] * &(this[4].double() - F::one()))
        &&
        // s1^2 - s2^2 = (1 + (endo - 1) * b2) * xt - xs
        this[2].square() - &this[3].square() == xq - &next[0]
        &&
        // (2*xp + (1 + (endo - 1) * b2) * xt – s1^2) * (s1 + s2) = 2*yp
        (next[2].double() + &xq - &this[2].square()) * &(this[2] + &this[3]) == next[3].double()
        &&
        // (xp – xs) * s2 = ys + yp
        (next[2] - &next[0]) * &this[3] == next[1] + &next[3]
    }

    pub fn endomul(&self) -> F {if self.typ == GateType::Endomul {F::one()} else {F::zero()}}
}
