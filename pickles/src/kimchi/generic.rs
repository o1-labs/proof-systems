
fn generic_gate() {
    let mut res = vec![];
                
    let mut generic_gate = |alpha_pow, register_offset| {
        let alpha_generic = alpha_pow * generic_zeta;

        // addition
        res.push(alpha_generic * w_zeta[register_offset]);
        res.push(alpha_generic * w_zeta[register_offset + 1]);
        res.push(alpha_generic * w_zeta[register_offset + 2]);

        // multplication
        res.push(alpha_generic * w_zeta[register_offset] * w_zeta[register_offset + 1]);

        // constant
        res.push(alpha_generic);
    };

    let alpha_pow1 = alphas
        .next()
        .expect("not enough alpha powers for generic gate");
    generic_gate(alpha_pow1, 0);

    let alpha_pow2 = alphas
        .next()
        .expect("not enough alpha powers for generic gate");
    generic_gate(alpha_pow2, GENERIC_REGISTERS);

    res
}