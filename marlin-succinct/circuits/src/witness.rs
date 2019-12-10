/*****************************************************************************************************************

This source file implements Marlin computation witness primitive.

*****************************************************************************************************************/

use algebra::Field;
pub use super::gate::CircuitGate;

// define witness as vector of assignments with the public part size
#[derive(Clone)]
pub struct Witness<F: Field>(pub Vec<F>, pub usize);

impl<F: Field> Witness<F>
{
    // This function creates zero-instance witness of given depth m with n public values
    pub fn create(m: usize, n: usize) -> Self
    {
        Witness::<F> (vec![F::zero(); m], n)
    }
}
