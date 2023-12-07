use ark_ec::AffineCurve;
use mina_curves::pasta::Pallas;

use crate::{
    alphas::Alphas,
    circuits::{
        argument::{ArgumentType, DynArgument},
        expr::{Cache, ConstantExpr, Expr},
        gate::GateType,
        polynomials::{
            foreign_field_add::circuitgates::{Conditional, ForeignFieldAdd},
            foreign_field_mul::circuitgates::ForeignFieldMul,
            generic::Generic,
            range_check::circuitgates::{RangeCheck0, RangeCheck1},
            rot::Rot64,
            xor::Xor16,
        },
    },
};
type PallasField = <Pallas as AffineCurve>::BaseField;

#[test]
fn test_to_and_from() {
    // Test polish to and from transform for all possible gates
    for gate in [
        &Conditional::<PallasField>::default() as &dyn DynArgument<PallasField>,
        &ForeignFieldAdd::<PallasField>::default(),
        &ForeignFieldMul::<PallasField>::default(),
        &Generic::<PallasField>::default(),
        &RangeCheck0::<PallasField>::default(),
        &RangeCheck1::<PallasField>::default(),
        &Rot64::<PallasField>::default(),
        &Xor16::<PallasField>::default(),
        // TODO: These won't work until Store/Load are supported
        // &CompleteAdd::<PallasField>::default()
        // &EndomulScalar::<PallasField>::default()
        // &EndosclMul::<PallasField>::default()
        // &Poseidon::<PallasField>::default()
        // &VarbaseMul::<PallasField>::default()
    ] {
        let mut alphas = Alphas::<PallasField>::default();
        alphas.register(ArgumentType::Gate(GateType::Zero), gate.constraint_count());
        assert_eq!(
            Expr::<ConstantExpr<PallasField>>::from_polish(
                &gate.to_polish(&alphas, &mut Cache::default())
            )
            .expect("parsed"),
            gate.combined_constraints(&alphas, &mut Cache::default())
        );
    }
}
