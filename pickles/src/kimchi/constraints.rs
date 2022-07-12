use ark_ff::{FftField, PrimeField};

use circuit_construction::{Cs, Var};

use crate::kimchi::alphas::Alphas;
use crate::kimchi::proof::VarEvaluations;

use crate::types::polynomials;
use crate::util::var_product;

use kimchi::circuits::polynomials::generic::GENERIC_REGISTERS;
use kimchi::circuits::wires::PERMUTS;

pub fn perm_scalar<F: FftField + PrimeField, C: Cs<F>>(
    cs: &mut C,
    evals: &VarEvaluations<F>,
    beta: Var<F>,
    gamma: Var<F>,
    alphas: &[Var<F>; 3],
    zkp_zeta: &polynomials::ZKPEval<F>,
) -> Var<F> {
    //~ Compute
    //~
    //~ $$
    //~ \begin{align}
    //~ z(\zeta \omega) \beta \alpha^{PERM0} zkpl(\zeta) \cdot \\
    //~ (\gamma + \beta \sigma_0(\zeta) + w_0(\zeta)) \cdot \\
    //~ (\gamma + \beta \sigma_1(\zeta) + w_1(\zeta)) \cdot \\
    //~ (\gamma + \beta \sigma_2(\zeta) + w_2(\zeta)) \cdot \\
    //~ (\gamma + \beta \sigma_3(\zeta) + w_3(\zeta)) \cdot \\
    //~ (\gamma + \beta \sigma_4(\zeta) + w_4(\zeta)) \cdot \\
    //~ (\gamma + \beta \sigma_5(\zeta) + w_5(\zeta)) \cdot \\
    //~ \end{align}
    //~$$
    //~

    // first term
    let mut prod = vec![
        evals.zetaw.z.clone().into(),
        beta,
        alphas[0],
        zkp_zeta.as_ref().clone(),
    ];

    // compute for every chunk of the committed permutation
    debug_assert_eq!(evals.zeta.s.len(), PERMUTS - 1);
    prod.extend((0..PERMUTS - 1).map(|i| {
        let si = evals.zeta.s[i].clone().into();
        let wi = evals.zeta.w[i].clone().into();

        // \beta * s
        let tmp = cs.mul(beta, si);

        // + w[i]
        let tmp = cs.add(tmp, wi);

        // + \gamma
        cs.add(tmp, gamma)
    }));

    var_product(cs, prod.into_iter())
}

// does two generic gates per row
pub fn generic_scalars<F: FftField + PrimeField, C: Cs<F>>(
    cs: &mut C,
    alphas: &[Var<F>],
    evals: &VarEvaluations<F>,
) -> Vec<Var<F>> {
    let mut res: Vec<Var<F>> = vec![];

    let mut generic_gate = |alpha_pow, register_offset: usize| {
        let alpha_generic = cs.mul(alpha_pow, evals.zeta.generic_selector.into());

        // addition
        res.push(cs.mul(alpha_generic, evals.zeta.w[register_offset].into()));
        res.push(cs.mul(alpha_generic, evals.zeta.w[register_offset + 1].into()));
        res.push(cs.mul(alpha_generic, evals.zeta.w[register_offset + 2].into()));

        // multplication
        let mul = cs.mul(
            evals.zeta.w[register_offset].into(),
            evals.zeta.w[register_offset + 1].into(),
        );
        res.push(cs.mul(alpha_generic, mul));

        // constant
        res.push(alpha_generic);
    };

    generic_gate(alphas[0], 0);
    generic_gate(alphas[1], GENERIC_REGISTERS);

    res
}
