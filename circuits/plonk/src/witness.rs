/*****************************************************************************************************************

This source file implements Plonk computation witness primitive.

*****************************************************************************************************************/

use algebra::Field;
use std::ops::Index;

#[derive(Clone)]
pub struct Witness<F: Field>
{
    pub secret: Vec<F>,
    pub public: Vec<F>
}

impl<F: Field> Witness<F>
{
    // This function creates zero-instance witness
    pub fn create(s: usize, p: usize) -> Self
    {
        Witness::<F> {secret: vec![F::zero(); s], public: vec![F::zero(); p]}
    }
}

impl<F: Field> Index<usize> for Witness<F>
where F: Field
{
    type Output = F;
    fn index(&self, index: usize) -> &F
    {
        if index < self.secret.len() {&self.secret[index]}
        else {&self.public[index-self.secret.len()]}
    }
}
