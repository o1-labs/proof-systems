use crate::bench::BenchmarkCtx;
use crate::proof::ProverProof;
use mina_curves::pasta::vesta::Affine;

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_serde() {
        let ctx = BenchmarkCtx::new(1 << 4);

        let proof = ctx.create_proof();

        // small check of proof being serializable
        let ser_pf = rmp_serde::to_vec(&proof).unwrap();
        println!("proof size: {} bytes", ser_pf.len());

        let de_pf: ProverProof<Affine> = rmp_serde::from_slice(&ser_pf).unwrap();

        ctx.batch_verification(vec![de_pf.clone()]);
    }
}
