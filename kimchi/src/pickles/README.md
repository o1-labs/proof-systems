# Pickles-rs

An implementation of Pickles in Rust.

## Roadmap

The idea is that it'll be easier to convert this to Rust if we start from self-contained parts.

- [ ] data structures
- [ ] composition types
- [ ] pickles types
- [ ] pickles base
- [ ] limb vector
- [ ] one hot vector
- [ ] pseudo
- [ ] etc.

## Cheat sheet

Here's a cheat sheet on the Mina pickles code base to help with the migration:

* pickles_types
  * pcs_batch: code to combine evaluations (should be moved to pickles)
  * shifted_value: prepare values for the scalar multiplication gate 
  * plonk_types: basically all the types. Also contain specs, which describe the types (and their lengths) so we can easily convert them to scalar bits
  * plonk_verification: the verification keys, rewritten in OCaml because we don't need to serialize all of the data in the Rust one (TODO: can't we just skip fields with serde in Rust?), we also rewrite types to use the vector GADTs (TODO: it'd be nice if ocaml-gen could be customized to generate labs AND/OR deriving sexp, and other functions)
* pickles_base
  * domain: obvious stuff
  * domains: artifact from Marlin (TODO: we can delete)
  * proofs_verified: refers to the number of proofs verified by a step circuit
  * side_loaded_verification_key: this refers to verification keys that are loaded dynamically, and we only use this in one place: zkapps (TODO: `domains` is repeated and can be deleted there) (TODO: two variables are attacker-controlled there: max_proofs_verified and actual_wrap_domain)
* pickles
  * limb_vector: vector of u64, used for challenges because we need to represent them as bits. Hex64 is a type created due to the lack of signed types (TODO: I think there are actual signed types in OCaml that we can use)
  * one_hot_vector: a vector with a single bit set to 1, it's a snarky type that uses the Nat GADT. Useful throughout pickles.
  * pseudo: a tuple `(one_hot_vector, vector_of_same_length)` that's useful to mask over verification keys, domains, generators, etc. in Pickles. Note that `seal` is redefined here (as well as `utils.ml`) and should probably be moved to snarky.
  * plonk_checks: compute ft_eval0 in-circuit
  * composition_types
    * spec: to specify the shape of other values. It's useful for two functions: pack and typ. This seems like a hard file to understand
    * bulletproof_challenge: just a wrapper type
    * branch_data: part of the statement describing the shape of the step circuit that was wrapped 
    * composition_types: types used in statements
