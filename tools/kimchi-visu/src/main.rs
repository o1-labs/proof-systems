use kimchi::{
    circuits::{
        gate::CircuitGate,
        polynomials::{generic::GenericGateSpec, poseidon},
        wires::Wire,
    },
    prover_index::testing::new_index_for_test,
};
use kimchi_visu::{visu, Witness};
use mina_curves::pasta::Fp;

fn main() {
    let public = 3;
    let poseidon_params = oracle::pasta::fp_kimchi::params();

    // create circuit
    let (gates, row) = {
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
            let round_constants = &poseidon_params.round_constants;
            let (g, row) = CircuitGate::<Fp>::create_poseidon_gadget(row, round_constants);
            gates.extend(g);
            row
        };

        // public input is output of poseidon
        let output_row = row - 1;
        gates[0].wires[0] = Wire { row, col: 0 };
        gates[1].wires[0] = Wire { row, col: 1 };
        gates[2].wires[0] = Wire { row, col: 2 };

        let poseidon_output = &mut gates[output_row].wires;
        poseidon_output[0] = Wire { row: 0, col: 0 };
        poseidon_output[1] = Wire { row: 0, col: 1 };
        poseidon_output[2] = Wire { row: 0, col: 2 };

        // range checks (using lookup)
        let row = {
            let wires = Wire::new(row);
            let g = CircuitGate::<Fp>::create_range(wires);
            gates.push(g);
            row + 1
        };

        (gates, row)
    };

    // create the index
    let index = new_index_for_test(gates, public);

    // create the witness
    let witness = {
        let mut witness = Witness::new(row + 1).inner();
        let input = [1u32.into(), 2u32.into(), 3u32.into()];
        poseidon::generate_witness(3, poseidon_params, &mut witness, input);

        // lookup
        witness[0][row] = 1u32.into();
        witness[1][row] = 1u32.into();
        witness[2][row] = 1u32.into();
        witness[3][row] = 1u32.into();
        witness[4][row] = 1u32.into();
        witness[5][row] = 1u32.into();
        witness[6][row] = 1u32.into();

        witness
    };

    // create the HTML
    visu(&index, Some(witness.into()));
}
