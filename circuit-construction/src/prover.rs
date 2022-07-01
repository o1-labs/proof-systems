use crate::writer::{Cs, GateSpec, System, Var, WitnessGenerator};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{FftField, One, PrimeField, SquareRootField, Zero};
use array_init::array_init;
use commitment_dlog::{
    commitment::{CommitmentCurve, PolyComm},
    srs::{endos, KimchiCurve, SRS},
};
use kimchi::{
    circuits::{constraints::ConstraintSystem, gate::GateType, wires::COLUMNS},
    plonk_sponge::FrSponge,
    proof::ProverProof,
    prover_index::ProverIndex,
};
use mina_curves::pasta::{fp::Fp, fq::Fq, pallas::Affine as Other, vesta::Affine};
use oracle::{poseidon::ArithmeticSpongeParams, FqSponge};

pub trait Cycle {
    type InnerField: FftField
        + PrimeField
        + SquareRootField
        + From<u128>
        + From<u64>
        + From<u32>
        + From<u16>
        + From<u8>;
    type OuterField: FftField
        + PrimeField
        + SquareRootField
        + From<u128>
        + From<u64>
        + From<u32>
        + From<u16>
        + From<u8>;

    type InnerMap: groupmap::GroupMap<Self::InnerField>;
    type OuterMap: groupmap::GroupMap<Self::OuterField>;

    type InnerProj: ProjectiveCurve<
            Affine = Self::Inner,
            ScalarField = Self::OuterField,
            BaseField = Self::InnerField,
        > + From<Self::Inner>
        + Into<Self::Inner>
        + std::ops::MulAssign<Self::OuterField>;

    type Inner: CommitmentCurve<
            Projective = Self::InnerProj,
            Map = Self::InnerMap,
            BaseField = Self::InnerField,
            ScalarField = Self::OuterField,
        > + From<Self::InnerProj>
        + Into<Self::InnerProj>;

    type OuterProj: ProjectiveCurve<
            Affine = Self::Outer,
            ScalarField = Self::InnerField,
            BaseField = Self::OuterField,
        > + From<Self::Outer>
        + Into<Self::Outer>
        + std::ops::MulAssign<Self::InnerField>;

    type Outer: CommitmentCurve<
            Projective = Self::OuterProj,
            Map = Self::OuterMap,
            ScalarField = Self::InnerField,
            BaseField = Self::OuterField,
        > + KimchiCurve;
}

pub struct FpInner;
pub struct FqInner;

impl Cycle for FpInner {
    type InnerMap = <Other as CommitmentCurve>::Map;
    type OuterMap = <Affine as CommitmentCurve>::Map;

    type InnerField = Fp;
    type OuterField = Fq;
    type Inner = Other;
    type Outer = Affine;
    type InnerProj = <Other as AffineCurve>::Projective;
    type OuterProj = <Affine as AffineCurve>::Projective;
}

impl Cycle for FqInner {
    type InnerMap = <Affine as CommitmentCurve>::Map;
    type OuterMap = <Other as CommitmentCurve>::Map;

    type InnerField = Fq;
    type OuterField = Fp;
    type Inner = Affine;
    type Outer = Other;
    type InnerProj = <Affine as AffineCurve>::Projective;
    type OuterProj = <Other as AffineCurve>::Projective;
}

/// Given an index, a group map, custom blinders for the witness, a public input vector, and a circuit `main`, create a proof.
pub fn prove<G, H, EFqSponge, EFrSponge>(
    index: &ProverIndex<G>,
    group_map: &G::Map,
    blinders: Option<[Option<G::ScalarField>; COLUMNS]>,
    public_input: Vec<G::ScalarField>,
    mut main: H,
) -> ProverProof<G>
where
    H: FnMut(&mut WitnessGenerator<G::ScalarField>, Vec<Var<G::ScalarField>>),
    G::BaseField: PrimeField,
    G: KimchiCurve,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    // create the public rows
    let mut gen: WitnessGenerator<G::ScalarField> = WitnessGenerator {
        rows: public_input
            .iter()
            .map(|x| array_init(|i| if i == 0 { *x } else { G::ScalarField::zero() }))
            .collect(),
    };

    // run the witness generation
    let public_vars = public_input
        .iter()
        .map(|x| Var {
            index: 0,
            value: Some(*x),
        })
        .collect();
    main(&mut gen, public_vars);

    // get the witness columns
    gen.curr_gate_count();
    let columns = gen.columns();

    // custom blinders for the witness commitment
    let blinders: [Option<PolyComm<G::ScalarField>>; COLUMNS] = match blinders {
        None => array_init(|_| None),
        Some(bs) => array_init(|i| {
            bs[i].map(|b| PolyComm {
                unshifted: vec![b],
                shifted: None,
            })
        }),
    };

    // create the proof
    ProverProof::create_recursive::<EFqSponge, EFrSponge>(
        group_map,
        columns,
        &[],
        index,
        vec![],
        Some(blinders),
    )
    .unwrap()
}

pub fn generate_prover_index<C, H>(
    srs: std::sync::Arc<SRS<C::Outer>>,
    poseidon_params: &ArithmeticSpongeParams<C::OuterField>,
    public: usize,
    main: H,
) -> ProverIndex<C::Outer>
where
    H: FnOnce(&mut System<C::Outer>, Vec<Var<C::InnerField>>),
    C: Cycle,
{
    let mut system: System<C::Outer> = System {
        next_variable: 0,
        gates: vec![],
    };
    let z = C::InnerField::zero();

    // create public input variables
    let public_input_row = vec![C::InnerField::one(), z, z, z, z, z, z, z, z, z];
    let public_input: Vec<_> = (0..public)
        .map(|_| {
            let v = system.var(|| panic!("fail"));
            let row = array_init(|i| {
                if i == 0 {
                    v
                } else {
                    system.var(|| panic!("fail"))
                }
            });
            system.gate(GateSpec {
                typ: GateType::Generic,
                c: public_input_row.clone(),
                row,
            });
            v
        })
        .collect();

    main(&mut system, public_input);

    let gates = system.gates();
    println!("gates: {}", gates.len());
    // Other base field = self scalar field
    let (endo_q, _endo_r) = endos::<C::Inner>();

    let constraint_system = ConstraintSystem::<C::Outer>::create(gates)
        .public(public)
        .build()
        // TODO: return a Result instead of panicking
        .expect("couldn't construct constraint system");

    ProverIndex::<C::Outer>::create(constraint_system, poseidon_params.clone(), endo_q, srs)
}

pub trait CoordinateCurve: AffineCurve {
    fn to_coords(&self) -> Option<(Self::BaseField, Self::BaseField)>;
}

impl<G: CommitmentCurve> CoordinateCurve for G {
    fn to_coords(&self) -> Option<(Self::BaseField, Self::BaseField)> {
        CommitmentCurve::to_coordinates(self)
    }
}
