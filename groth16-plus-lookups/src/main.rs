use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
use groth16_plus_lookups::{
    prover::{prove_stage_1, prove_stage_2},
    proving_key::{trusted_setup, CircuitLayout},
    verifier::verify,
};

type BN254 = ark_ec::bn::Bn<ark_bn254::Parameters>;

struct LayoutPerRow {
    a: Vec<(usize, Fr)>,
    b: Vec<(usize, Fr)>,
    c: Vec<(usize, Fr)>,
    a_delayed: Vec<(usize, Fr)>,
    c_equality: Vec<(usize, Fr)>,
}

fn create_layout(
    domain_size: usize,
    public_input_size: usize,
    witness_size: usize,
    layout: Vec<LayoutPerRow>,
) -> CircuitLayout<Fr> {
    let domain = D::new(domain_size).unwrap();
    let domain_d2 = D::new(domain_size << 1).unwrap();

    let mut a_contributions = vec![vec![]; witness_size];
    let mut b_contributions = vec![vec![]; witness_size];
    let mut c_contributions = vec![vec![]; witness_size];
    let mut a_delayed_contributions = vec![vec![]; witness_size];
    let mut c_delayed_equality_contributions = vec![vec![]; witness_size];

    for (row_idx, row_layout) in layout.into_iter().enumerate() {
        for (idx, scalar) in row_layout.a {
            a_contributions[idx].push((row_idx, scalar));
        }
        for (idx, scalar) in row_layout.b {
            b_contributions[idx].push((row_idx, scalar));
        }
        for (idx, scalar) in row_layout.c {
            c_contributions[idx].push((row_idx, scalar));
        }
        for (idx, scalar) in row_layout.a_delayed {
            a_delayed_contributions[idx].push((row_idx, scalar));
        }
        for (idx, scalar) in row_layout.c_equality {
            c_delayed_equality_contributions[idx].push((row_idx, scalar));
        }
    }

    CircuitLayout {
        public_input_size,
        a_contributions: a_contributions
            .into_iter()
            .map(|x| x.into_boxed_slice())
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        a_delayed_contributions: a_delayed_contributions
            .into_iter()
            .map(|x| x.into_boxed_slice())
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        b_contributions: b_contributions
            .into_iter()
            .map(|x| x.into_boxed_slice())
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        c_contributions: c_contributions
            .into_iter()
            .map(|x| x.into_boxed_slice())
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        c_delayed_equality_contributions: c_delayed_equality_contributions
            .into_iter()
            .map(|x| x.into_boxed_slice())
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        domain,
        domain_d2,
    }
}

pub fn main() {
    let size = 1 << 5;
    let public_input_size = 3;

    let mut witness = vec![];
    let mut store = |x| {
        let idx = witness.len();
        witness.push(x);
        idx
    };

    // Public
    let constant_1 = store(Fr::from(1u64));
    let delayed_lookup_randomizer = store(Fr::from(0u64));
    let delayed_lookup_table_combiner = store(Fr::from(0u64));

    // Private
    let x_1 = store(Fr::from(4u64));
    let x_2 = store(Fr::from(16u64));

    let layout = create_layout(
        size,
        public_input_size,
        witness.len(),
        vec![
            LayoutPerRow {
                a: vec![(constant_1, Fr::from(1u64))],
                b: vec![(constant_1, Fr::from(2u64))],
                c: vec![(x_1, Fr::from(1u64))],
                a_delayed: vec![(constant_1, Fr::from(1u64))],
                c_equality: vec![(constant_1, Fr::from(1u64))],
            },
            LayoutPerRow {
                a: vec![(x_1, Fr::from(1u64))],
                b: vec![(x_1, Fr::from(1u64))],
                c: vec![(x_2, Fr::from(1u64))],
                a_delayed: vec![],
                c_equality: vec![],
            },
        ],
    );

    let (prover_setup, vk) = trusted_setup::<_, _, BN254>(&layout, &mut rand::rngs::OsRng);

    let prover_env = prove_stage_1::<_, _, BN254>(
        witness.as_slice(),
        &prover_setup,
        &layout,
        &mut rand::rngs::OsRng,
    );

    // Update witness with now-known values
    {
        use ark_ff::UniformRand;

        // TODO: Fiat shamir
        let lookup_randomizer = Fr::rand(&mut rand::rngs::OsRng);
        let lookup_table_combiner = Fr::rand(&mut rand::rngs::OsRng);

        witness[1] = lookup_randomizer;
        witness[2] = lookup_table_combiner;
    }

    let proof = prove_stage_2::<_, BN254>(prover_env, witness.as_slice(), &prover_setup, &layout);

    let public_input: Vec<_> = witness[0..public_input_size]
        .into_iter()
        .map(|x| x.into_repr())
        .collect();

    let verifies = verify::<BN254>(public_input.as_slice(), &proof, &vk);

    println!("verifies? {}", verifies);
}
