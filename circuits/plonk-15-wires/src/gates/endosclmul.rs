/*****************************************************************************************************************

This source file implements group endomorphism optimised
variable base scalar multiplication custom Plonk constraints.

EVBSM gate constraints
	b1*(b1-1) = 0
	b2*(b2-1) = 0
	b3*(b3-1) = 0
	b4*(b4-1) = 0
	((1 + (endo - 1) * b2) * xt - xp) * s1 = (2*b1-1)*yt - yp
	(2*xp – s1^2 + (1 + (endo - 1) * b2) * xt) * ((xp – xr) * s1 + yr + yp) = (xp – xr) * 2*yp
	(yr + yp)^2 = (xp – xr)^2 * (s1^2 – (1 + (endo - 1) * b2) * xt + xr)
	((1 + (endo - 1) * b2) * xt - xr) * s3 = (2*b3-1)*yt - yr
	(2*xr – s3^2 + (1 + (endo - 1) * b4) * xt) * ((xr – xs) * s3 + ys + yr) = (xr – xs) * 2*yr
	(ys + yr)^2 = (xr – xs)^2 * (s3^2 – (1 + (endo - 1) * b4) * xt + xs)
	n_next = 16*n + 8*b1 + 4*b2 + 2*b3 + b4

The constraints above are derived from the following EC Affine arithmetic equations:

    (xq1 - xp) * s1 = yq1 - yp
    (2*xp – s1^2 + xq1) * ((xp – xr) * s1 + yr + yp) = (xp – xr) * 2*yp
    (yr + yp)^2 = (xp – xr)^2 * (s1^2 – xq1 + xr)

    (xq2 - xr) * s3 = yq2 - yr
    (2*xr – s3^2 + xq2) * ((xr – xs) * s3 + ys + yr) = (xr – xs) * 2*yr
    (ys + yr)^2 = (xr – xs)^2 * (s3^2 – xq2 + xs)

*****************************************************************************************************************/

use algebra::FftField;
use crate::gate::{CircuitGate, GateType};
use crate::{wires::{GateWires, COLUMNS}, nolookup::constraints::ConstraintSystem};
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
        let xq1 = (F::one() + &((cs.endo - &F::one()) * &next[12])) * &this[0];
        let xq2 = (F::one() + &((cs.endo - &F::one()) * &next[14])) * &this[0];
        
        self.typ == GateType::Endomul
        &&
        [
            // verify booleanity of the scalar bits
            this[11] - this[11].square(),
            this[12] - this[12].square(),
            this[13] - this[13].square(),
            this[14] - this[14].square(),

            (xq1 - this[4]) * this[9] - (this[11].double()-F::one())*this[2] + this[5],
            (this[4].double() - this[9].square() + xq1) * ((this[4] - this[7]) * this[9] + this[8] + this[5]) - (this[4] - this[7]) * this[5].double(),
            (this[8] + this[5]).square() - (this[4] - this[7]).square() * (this[9].square() - xq1 + this[7]),

            (xq2 - this[7]) * this[10] - (this[13].double()-F::one())*this[2] + this[8],
            (this[7].double() - this[10].square() + xq2) * ((this[7] - this[2]) * this[10] + this[3] + this[8]) - (this[7] - this[2]) * this[8].double(),
            (this[3] + this[8]).square() - (this[7] - this[2]).square() * (this[10].square() - xq2 + this[2]),
            
            (((witness[6][self.row+1].double() + this[11]).double() + this[12]).double() + this[13]).double() + this[14] - this[6],
        ].iter().all(|p| *p == F::zero())
    }

    pub fn endomul(&self) -> F {if self.typ == GateType::Endomul {F::one()} else {F::zero()}}
}
