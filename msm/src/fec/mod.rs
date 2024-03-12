pub mod columns;
pub mod constraint;
pub mod interpreter;
pub mod witness;

#[cfg(test)]
mod tests {

    use crate::fec::{
        interpreter::{self as fec_interpreter, FECInterpreterEnv},
        witness::WitnessBuilderEnv as FECWitnessBuilderEnv,
    };
    use crate::{Ff1, Fp};
    use ark_ff::UniformRand;
    //use rand::Rng;

    #[test]
    /// Builds the FF addition circuit with random values. The witness
    /// environment enforces the constraints internally, so it is
    /// enough to just build the circuit to ensure it is satisfied.
    pub fn test_foreign_field_addition_circuit() {
        let mut rng = o1_utils::tests::make_test_rng();
        //let domain_size = 1 << 8;

        let mut witness_env = FECWitnessBuilderEnv::<Fp>::empty();

        //let row_num = rng.gen_range(0..domain_size);
        let row_num = 1;

        for _row_i in 0..row_num {
            let xp: Ff1 = <Ff1 as UniformRand>::rand(&mut rng);
            let yp: Ff1 = <Ff1 as UniformRand>::rand(&mut rng);
            let xq: Ff1 = <Ff1 as UniformRand>::rand(&mut rng);
            let yq: Ff1 = <Ff1 as UniformRand>::rand(&mut rng);

            //use rand::Rng;
            //let a: Ff1 = From::from(rng.gen_range(0..(1 << 50)));
            //let b: Ff1 = From::from(rng.gen_range(0..(1 << 50)));
            fec_interpreter::ec_add_circuit(&mut witness_env, 0, xp, yp, xq, yq);
            witness_env.next_row();
        }
    }
}
