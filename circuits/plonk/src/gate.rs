/*****************************************************************************************************************

This source file implements Plonk computation wire index primitive.

*****************************************************************************************************************/

use algebra::Field;

pub const SPONGE_WIDTH: usize = oracle::poseidon::SPONGE_CAPACITY + oracle::poseidon::SPONGE_RATE;

#[derive(Clone)]
pub struct CircuitGate<F: Field>
{
    pub l: (usize, usize), // left input wire index and its permutation
    pub r: (usize, usize), // right input wire index and its permutation
    pub o: (usize, usize), // output wire index and its permutation

    // generic gate selectors
    pub ql: F, // left input selector
    pub qr: F, // right input selector
    pub qo: F, // output selector
    pub qm: F, // multiplication selector
    pub qc: F, // constant selector

    // poseidon gate selectors
    pub ps: F, // poseidon selector
    pub rc: [F; SPONGE_WIDTH], // round constant selectors
    pub ip: F, // indicator selector
}

impl<F: Field> CircuitGate<F>
{
    // this function creates "empty" circuit gate
    pub fn zero () -> Self
    {
        CircuitGate
        {
            l: (0, 0),
            r: (0, 0),
            o: (0, 0),
            ql: F::zero(),
            qr: F::zero(),
            qo: F::zero(),
            qm: F::zero(),
            qc: F::zero(),
            ps: F::zero(),
            rc: [F::zero(); 3],
            ip: F::zero(),
        }
    }

    pub fn create
    (
        l: (usize, usize),
        r: (usize, usize),
        o: (usize, usize),
        ql: F,
        qr: F,
        qo: F,
        qm: F,
        qc: F,
        ps: F,
        rc: [F; 3],
        ip: F,
    ) -> Self
    {
        CircuitGate
        {
            l,
            r,
            o,
            ql,
            qr,
            qo,
            qm,
            qc,
            ps,
            rc,
            ip,
        }
    }
}
