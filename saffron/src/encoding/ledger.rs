pub struct Account {
    // Dummy, should be a pk, but it is only for the demo.
    address: u32,
    balance: u32,
}

pub struct Ledger {
    accounts: Vec<Account>,
}

impl AbstractState for Ledger {
    fn encoded_length(&self) -> usize {
        self.accounts.len()
    }

    fn encode<F: PrimeField>(
        &self,
        domain: Radix2EvaluationDomain<F>,
    ) -> Vec<Evaluations<F, Radix2EvaluationDomain<F>>> {
        let mut evals: Vec<F> = self
            .accounts
            .iter()
            .map(|a| {
                let encoding: u64 = (a.address as u64) << 32 | a.balance as u64;
                F::from(encoding)
            })
            .collect();
        let current_length: usize = evals.len();
        let domain_size: usize = domain.size as usize;
        let padded_length_to_multiple_domain_size: usize =
            domain_size * ((current_length + domain_size - 1) / domain_size);
        let pad_length: usize = padded_length_to_multiple_domain_size - current_length;
        evals.extend(std::iter::repeat(F::zero()).take(pad_length));
        let splitted_evals: Vec<Vec<F>> = evals.chunks(domain_size).map(|c| c.to_vec()).collect();
        splitted_evals
            .into_iter()
            .map(|e| Evaluations::from_vec_and_domain(e, domain))
            .collect()
    }
}
