# Booleans

Booleans are a good example of a [snarky variable](./vars.md#snarky-vars).

```rust
pub struct Boolean<F: PrimeField>(FieldVar<F>);

impl<F> SnarkyType<F> for Boolean<F>
where
    F: PrimeField,
{
    type Auxiliary = ();

    type OutOfCircuit = bool;

    const SIZE_IN_FIELD_ELEMENTS: usize = 1;

    fn to_cvars(&self) -> (Vec<FieldVar<F>>, Self::Auxiliary) {
        (vec![self.0.clone()], ())
    }

    fn from_cvars_unsafe(cvars: Vec<FieldVar<F>>, _aux: Self::Auxiliary) -> Self {
        assert_eq!(cvars.len(), Self::SIZE_IN_FIELD_ELEMENTS);
        Self(cvars[0].clone())
    }

    fn check(&self, cs: &mut RunState<F>) {
        // TODO: annotation?
        cs.assert_(Some("boolean check"), vec![BasicSnarkyConstraint::Boolean(self.0.clone())]);
    }

    fn deserialize(&self) -> (Self::OutOfCircuit, Self::Auxiliary) {
        todo!()
    }

    fn serialize(out_of_circuit: Self::OutOfCircuit, aux: Self::Auxiliary) -> Self {
        todo!()
    }

    fn constraint_system_auxiliary() -> Self::Auxiliary {
        todo!()
    }

    fn value_to_field_elements(x: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary) {
        todo!()
    }

    fn value_of_field_elements(x: (Vec<F>, Self::Auxiliary)) -> Self::OutOfCircuit {
        todo!()
    }
}
```

## Check

The `check()` function is simply constraining the `FieldVar` $x$ to be either
$0$ or $1$ using the following constraint:

$$x ( x - 1) = 0$$

It is trivial to use the
[double generic gate](../specs/kimchi.md#double-generic-gate) for this.

## And

$$x \land y = x \times y$$

## Not

$$\sim x = 1 - x$$

## Or

- $\sim x \land \sim y = b$
- $x \lor y = \sim b$
