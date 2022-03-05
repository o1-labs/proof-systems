use commitment_dlog::srs::{endos, SRS};
use kimchi::{
    circuits::{
        constraints::ConstraintSystem, gate::CircuitGate, polynomials::generic::GenericGateSpec,
        wires::Wire,
    },
    index::Index,
};
use kimchi_visu::visu;
use mina_curves::pasta::{pallas::Affine as Other, vesta::Affine, Fp};
use std::sync::Arc;

fn main() {
    let public = 3;

    // create circuit
    let gates = {
        let mut gates = vec![];

        // public input
        let row = {
            for i in 0..public {
                let g = CircuitGate::<Fp>::create_generic_gadget(
                    Wire::new(i),
                    GenericGateSpec::Pub,
                    None,
                );
                gates.push(g);
            }
            public
        };

        // poseidon
        let row = {
            let round_constants = oracle::pasta::fp::params().round_constants;
            let (g, row) = CircuitGate::<Fp>::create_poseidon_gadget(
                row,
                [Wire::new(row), Wire::new(row + 11)],
                &round_constants,
            );
            gates.extend(g);
            row
        };

        // public input is output of poseidon
        {
            gates[0].wires[0] = Wire { row, col: 0 };
            gates[1].wires[0] = Wire { row, col: 1 };
            gates[2].wires[0] = Wire { row, col: 2 };

            let poseidon_output = &mut gates[row].wires;
            poseidon_output[0] = Wire { row: 0, col: 0 };
            poseidon_output[1] = Wire { row: 0, col: 1 };
            poseidon_output[2] = Wire { row: 0, col: 2 };
        }

        gates
    };

    // create the constraint system
    let cs =
        ConstraintSystem::<Fp>::create(gates, vec![], oracle::pasta::fp::params(), public).unwrap();

    // create the SRS
    let mut srs = SRS::<Affine>::create(cs.domain.d1.size as usize);
    srs.add_lagrange_basis(cs.domain.d1);
    let srs = Arc::new(srs);

    // create the index
    let index = {
        let fq_sponge_params = oracle::pasta::fq::params();
        let (endo_q, _endo_r) = endos::<Other>();
        Index::<Affine>::create(cs, fq_sponge_params, endo_q, srs)
    };

    // create the HTML
    visu(&index, None);
}
