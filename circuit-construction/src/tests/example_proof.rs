use crate::prologue::*;
use kimchi::curve::KimchiCurve;

type SpongeQ = DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>;
type SpongeR = DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>;

pub struct Witness<G: AffineCurve> {
    pub s: G::ScalarField,
    pub preimage: G::BaseField,
}

// Prove knowledge of discrete log and poseidon preimage of a hash
pub fn circuit<
    F: PrimeField + FftField,
    G: AffineCurve<BaseField = F> + CoordinateCurve,
    Sys: Cs<F>,
>(
    constants: &Constants<F>,
    // The witness
    witness: Option<&Witness<G>>,
    sys: &mut Sys,
    public_input: Vec<Var<F>>,
) {
    let zero = sys.constant(F::zero());

    let constant_curve_pt = |sys: &mut Sys, (x, y)| {
        let x = sys.constant(x);
        let y = sys.constant(y);
        (x, y)
    };

    let base = constant_curve_pt(sys, G::prime_subgroup_generator().to_coords().unwrap());
    let scalar = sys.scalar(G::ScalarField::size_in_bits(), || {
        witness.as_ref().unwrap().s
    });
    let actual = sys.scalar_mul(zero, base, scalar);

    let preimage = sys.var(|| witness.as_ref().unwrap().preimage);
    let actual_hash = sys.poseidon(constants, vec![preimage, zero, zero])[0];

    sys.assert_eq(actual.0, public_input[0]);
    sys.assert_eq(actual.1, public_input[1]);
    sys.assert_eq(actual_hash, public_input[2]);
}

const PUBLIC_INPUT_LENGTH: usize = 3;

#[test]
fn test_example_circuit() {
    use mina_curves::pasta::Pallas;
    use mina_curves::pasta::Vesta;
    // create SRS
    let srs = {
        let mut srs = SRS::<Vesta>::create(1 << 7); // 2^7 = 128
        srs.add_lagrange_basis(Radix2EvaluationDomain::new(srs.g.len()).unwrap());
        Arc::new(srs)
    };

    let proof_system_constants = fp_constants();

    // generate circuit and index
    let prover_index = generate_prover_index::<_, _>(srs, PUBLIC_INPUT_LENGTH, |sys, p| {
        circuit::<_, Pallas, _>(&proof_system_constants, None, sys, p)
    });

    let group_map = <Vesta as CommitmentCurve>::Map::setup();

    let mut rng = rand::thread_rng();

    // create witness
    let private_key = <Pallas as AffineCurve>::ScalarField::rand(&mut rng);
    let preimage = <Pallas as AffineCurve>::BaseField::rand(&mut rng);

    let witness = Witness {
        s: private_key,
        preimage,
    };

    // create public input
    let public_key = Pallas::prime_subgroup_generator()
        .mul(private_key)
        .into_affine();
    let hash = {
        let mut s: ArithmeticSponge<_, PlonkSpongeConstantsKimchi> =
            ArithmeticSponge::new(Vesta::sponge_params());
        s.absorb(&[preimage]);
        s.squeeze()
    };

    // generate proof
    let public_input = vec![public_key.x, public_key.y, hash];
    let proof = prove::<Vesta, _, SpongeQ, SpongeR>(
        &prover_index,
        &group_map,
        None,
        &public_input,
        |sys, p| circuit::<Fp, Pallas, _>(&proof_system_constants, Some(&witness), sys, p),
    );

    // verify proof
    let verifier_index = prover_index.verifier_index();

    verify::<_, SpongeQ, SpongeR>(&group_map, &verifier_index, &proof, &public_input).unwrap();
}
