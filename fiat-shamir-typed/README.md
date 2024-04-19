## Typed Fiat Shamir

This is an attempt to type the Fiat Shamir transform and to add type-safeness to IOP protocols.

Inspiration might come from different libraries and conversations with some persons:
- Michele Orru at zkSummit 10, after discussion his library [...] (missing links)
- Francois Garillot and his library [...] (missing links)
- Matthew Ryan

I try to design it from scratch, and similarities with other works should be
mentioned. If you think there are missing credits, please, let me know.
Some designs might be inspired from
previous designs I wrote in OCaml. For instance, particular the permutation and the sponge mode comes from
[ocaml-bls12-381-hash](https://gitlab.com/nomadic-labs/cryptography/ocaml-bls12-381-hash).

### Sponge design

The first thing to design is the mode of operation `Sponge`.
The mode relies on an internal permutation, working on a state of size `N`. The
permutation should be interchangeable (i.e. Hades/Poseidon/Poseidon2, Rescue, Griffin, Anemoi,
etc).
The natural idea is to represent the internal permutation using a trait `PERMUTATION`, parametrized by, at least, two types:
- the size of the internal state
- the field the state uses

```
pub trait Permutation<F: Field, const STATE_SIZE: usize> {
    fn apply_permutation(&self);
}
```

We also want to let the user absorbing different kind of types (field elements,
bytes, group points, etc), i.e. the types should be `absorbable`.

### Sypnosis

The first design attempts to type the transcript for a generic PlonK PIOP, using KZG.
