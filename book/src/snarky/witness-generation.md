# Witness generation

In snarky, currently, the same code is run through again to generate the witness.

That is, the `RunState` contains a few changes:

* **`public_input: Vec<F>`**: now contains concrete values (instead of being empty).
* **`has_witness`**: is set to `WitnessGeneration`.

Additionaly, if we want to verify that the arguments are actually correct (and that the program implemented does not fail) we can also set `eval_constraints` to `true` (defaults to `false`) to verify that the program has a correct state at all point in time.

```admonish
This is implemented by simply checking that each [generic gate]() encountered is correct, in relation to the witness values observed in that row. In other words $c_0 l + c_1 r + c_2 o + c_3 l r + c_4 = 0$ (extrapolated to the [double generic gate](../specs/kimchi.md#double-generic-gate)).
```

Due to the `has_witness` variable set to `WitnessGeneration`, functions will behave differently and compute actual values instead of generating constraints.
