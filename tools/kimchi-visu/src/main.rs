use kimchi::{
    circuits::{gate::CircuitGate, polynomials::generic::GenericGateSpec, wires::Wire},
    index::testing::new_index_for_test,
};
use kimchi_visu::visu;
use mina_curves::pasta::Fp;

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

    // create the index
    let index = new_index_for_test(gates, public);

    // create the HTML
    visu(&index, None);
}
