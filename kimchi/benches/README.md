# Prover benches

These are written to be cherry-picked onto any branch and run there, so the same
numbers can be compared across branches. They touch only new files plus an
append to `kimchi/Cargo.toml`.

| Bench                    | Measures                                                             | Relevant to  |
| ------------------------ | -------------------------------------------------------------------- | ------------ |
| `perm_quot`              | `ProverIndex::perm_quot`, plus `create_proof` for the share of total | #3586, #3589 |
| `dce_create`             | `DomainConstantEvaluations::create`, 2^12–2^18                       | #3586        |
| `constraint_evals`       | `Expr::evaluations` for the d4 and d8 gate constraints               | #3588        |
| `alloc_report` (example) | Bytes allocated, retained and peak                                   | all          |

```sh
cargo bench -p kimchi --bench perm_quot
cargo run --release -p kimchi --example alloc_report
```

`perm_quot` and `constraint_evals` rebuild the prover's inputs the way
`ProverProof::create` does — same witness padding, zk-row randomisation, real
permutation accumulator — so they measure production-shaped data.

Two things to watch when comparing across branches:

- Build each branch with its own `CARGO_TARGET_DIR`. Cargo gives two worktrees
  of the same package the same artifact hash and will silently reuse one
  branch's binary for the other.
- A single pair of cross-branch runs is not reliable. Long all-core benches
  drift by ~10% over a session, which is larger than most of the effects being
  measured. Alternate the branches over several rounds and compare paired
  deltas.
