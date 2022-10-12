use std::ops::{Add, Neg, Sub};

use ark_ff::PrimeField;

use crate::{
    loc,
    snarky::{
        boolean::Boolean,
        checked_runner::{RunState, WitnessGeneration},
        constraint_system::SnarkyCvar,
        traits::SnarkyType,
    },
};

/// A circuit variable represents a field element in the circuit.
#[derive(Clone, Debug)]
pub enum CVar<F>
where
    F: PrimeField,
{
    Constant(F),
    Var(usize),
    Add(Box<CVar<F>>, Box<CVar<F>>),
    Scale(F, Box<CVar<F>>),
}

impl<F> SnarkyCvar for CVar<F>
where
    F: PrimeField,
{
    type Field = F;

    fn to_constant_and_terms(&self) -> (Option<Self::Field>, Vec<(Self::Field, usize)>) {
        self.to_constant_and_terms()
    }
}

pub type Term<F> = (F, usize);

pub type ScaledCVar<F> = (F, CVar<F>);

impl<F> CVar<F>
where
    F: PrimeField,
{
    fn eval_inner(&self, context: &impl (Fn(usize) -> F), scale: F, res: &mut F) {
        match self {
            CVar::Constant(c) => {
                *res += scale * c;
            }
            CVar::Var(v) => {
                let v = context(*v); // TODO: might panic
                *res += scale * v;
            }
            CVar::Add(a, b) => {
                a.eval_inner(context, scale, res);
                b.eval_inner(context, scale, res);
            }
            CVar::Scale(s, v) => {
                v.eval_inner(context, scale * s, res);
            }
        }
    }

    /// Evaluate the field element associated to a variable (used during witness generation)
    pub fn eval(&self, context: &impl (Fn(usize) -> F)) -> F {
        let mut res = F::zero();
        self.eval_inner(context, F::one(), &mut res);
        res
    }

    pub fn to_constant_and_terms_inner(
        &self,
        scale: F,
        constant: F,
        terms: Vec<Term<F>>,
    ) -> (F, Vec<Term<F>>) {
        match self {
            CVar::Constant(c) => (constant + (scale * c), terms),
            CVar::Var(v) => {
                let mut new_terms = vec![(scale, *v)];
                new_terms.extend(terms);
                (constant, new_terms)
            }
            CVar::Scale(s, t) => t.to_constant_and_terms_inner(scale * s, constant, terms),
            CVar::Add(x1, x2) => {
                let (c1, terms1) = x1.to_constant_and_terms_inner(scale, constant, terms);
                x2.to_constant_and_terms_inner(scale, c1, terms1)
            }
        }
    }

    pub fn to_constant_and_terms(&self) -> (Option<F>, Vec<Term<F>>) {
        let (constant, terms) = self.to_constant_and_terms_inner(F::one(), F::zero(), vec![]);
        let constant = if constant.is_zero() {
            None
        } else {
            Some(constant)
        };
        (constant, terms)
    }

    pub fn scale(&self, scalar: F) -> Self {
        if scalar.is_zero() {
            return CVar::Constant(scalar);
        } else if scalar.is_one() {
            return self.clone();
        }

        match self {
            CVar::Constant(x) => CVar::Constant(*x * scalar),
            CVar::Scale(s, v) => CVar::Scale(*s * scalar, v.clone()),
            CVar::Var(_) | CVar::Add(..) => CVar::Scale(scalar, Box::new(self.clone())),
        }
    }

    pub fn linear_combination(terms: &[ScaledCVar<F>]) -> Self {
        let mut res = CVar::Constant(F::zero());
        for (cst, term) in terms {
            res = res.add(&term.scale(*cst));
        }
        res
    }

    pub fn sum(vs: &[&Self]) -> Self {
        let terms: Vec<_> = vs.iter().map(|v| (F::one(), (*v).clone())).collect();
        Self::linear_combination(&terms)
    }

    pub fn mul(&self, other: &Self, label: Option<&'static str>, cs: &mut RunState<F>) -> Self {
        match (self, other) {
            (CVar::Constant(x), CVar::Constant(y)) => CVar::Constant(*x * y),

            // TODO: this was not in the original ocaml code, but seems correct to me
            (CVar::Constant(cst), _) | (_, CVar::Constant(cst)) if cst.is_zero() => {
                CVar::Constant(F::zero())
            }

            // TODO: same here
            (CVar::Constant(cst), cvar) | (cvar, CVar::Constant(cst)) if cst.is_one() => {
                cvar.clone()
            }

            (CVar::Constant(cst), cvar) | (cvar, CVar::Constant(cst)) => cvar.scale(*cst),

            (_, _) => {
                let self_clone = self.clone();
                let other_clone = other.clone();
                let res: CVar<F> = cs.compute(loc!(), move |env| {
                    let x: F = env.read_var(&self_clone);
                    let y: F = env.read_var(&other_clone);
                    x * y
                });

                let label = label.or(Some("checked_mul"));

                cs.assert_r1cs(label, self.clone(), other.clone(), res.clone());
                res
            }
        }
    }

    /** [equal_constraints z z_inv r] asserts that
       if z = 0 then r = 1, or
       if z <> 0 then r = 0 and z * z_inv = 1
    */
    fn equal_constraints(state: &mut RunState<F>, z: Self, z_inv: Self, r: Self) {
        // TODO: the ocaml code actually calls assert_all
        let one_minus_r = CVar::Constant(F::one()) - &r;
        let zero = CVar::Constant(F::zero());
        state.assert_r1cs(Some("equals_1"), z_inv, z.clone(), one_minus_r);
        state.assert_r1cs(Some("equals_2"), r, z, zero);
    }

    /** [equal_vars z] computes [(r, z_inv)] that satisfy the constraints in
    [equal_constraints z z_inv r].

    In particular, [r] is [1] if [z = 0] and [0] otherwise.
    */
    fn equal_vars(env: &dyn WitnessGeneration<F>, z: &CVar<F>) -> (F, F) {
        let z: F = env.read_var(z);
        if let Some(z_inv) = z.inverse() {
            (F::zero(), z_inv)
        } else {
            (F::one(), F::zero())
        }
    }

    pub fn equal(&self, state: &mut RunState<F>, other: &CVar<F>) -> Boolean<F> {
        match (self, other) {
            (CVar::Constant(x), CVar::Constant(y)) => {
                let res = if x == y { F::one() } else { F::zero() };
                let cvars = vec![CVar::Constant(res)];
                Boolean::from_cvars_unsafe(cvars, ())
            }
            _ => {
                let z = self - other;
                let z_clone = z.clone();
                let (res, z_inv): (CVar<F>, CVar<F>) =
                    state.compute(loc!(), move |env| Self::equal_vars(env, &z_clone));
                Self::equal_constraints(state, z, z_inv, res.clone());

                let cvars = vec![res];
                Boolean::from_cvars_unsafe(cvars, ())
            }
        }
    }

    /*
    let equal (x : Cvar.t) (y : Cvar.t) : Cvar.t Boolean.t t =
      match (x, y) with
      | Constant x, Constant y ->
          Checked.return
            (Boolean.Unsafe.create
               (Cvar.constant
                  (if Field.equal x y then Field.one else Field.zero) ) )
      | _ ->
          let z = Cvar.(x - y) in
          let%bind r, inv =
            exists Typ.(field * field) ~compute:(equal_vars z)
          in
          let%map () = equal_constraints z inv r in
          Boolean.Unsafe.create r */
}

/*

        let assert_equal ?label x y =
      match (x, y) with
      | Cvar0.Constant x, Cvar0.Constant y ->
          if Field.equal x y then return ()
          else
            failwithf
              !"assert_equal: %{sexp: Field.t} != %{sexp: Field.t}"
              x y ()
      | _ ->
          assert_equal ?label x y

    (* [equal_constraints z z_inv r] asserts that
       if z = 0 then r = 1, or
       if z <> 0 then r = 0 and z * z_inv = 1
    *)
    let equal_constraints (z : Cvar.t) (z_inv : Cvar.t) (r : Cvar.t) =
      let open Constraint in
      let open Cvar in
      assert_all
        [ r1cs ~label:"equals_1" z_inv z (Cvar.constant Field.one - r)
        ; r1cs ~label:"equals_2" r z (Cvar.constant Field.zero)
        ]

    (* [equal_vars z] computes [(r, z_inv)] that satisfy the constraints in
       [equal_constraints z z_inv r].

       In particular, [r] is [1] if [z = 0] and [0] otherwise.
    *)
    let equal_vars (z : Cvar.t) : (Field.t * Field.t) As_prover.t =
      let open As_prover in
      let%map z = read_var z in
      if Field.equal z Field.zero then (Field.one, Field.zero)
      else (Field.zero, Field.inv z)

    let equal (x : Cvar.t) (y : Cvar.t) : Cvar.t Boolean.t t =
      match (x, y) with
      | Constant x, Constant y ->
          Checked.return
            (Boolean.Unsafe.create
               (Cvar.constant
                  (if Field.equal x y then Field.one else Field.zero) ) )
      | _ ->
          let z = Cvar.(x - y) in
          let%bind r, inv =
            exists Typ.(field * field) ~compute:(equal_vars z)
          in
          let%map () = equal_constraints z inv r in
          Boolean.Unsafe.create r


    let square ?(label = "Checked.square") (x : Cvar.t) =
      match x with
      | Constant x ->
          return (Cvar.constant (Field.square x))
      | _ ->
          with_label label
            (let open Let_syntax in
            let%bind z =
              exists Typ.field
                ~compute:As_prover.(map (read_var x) ~f:Field.square)
            in
            let%map () = assert_square x z in
            z)

    (* We get a better stack trace by failing at the call to is_satisfied, so we
       put a bogus value for the inverse to make the constraint system unsat if
       x is zero. *)
    let inv ?(label = "Checked.inv") (x : Cvar.t) =
      match x with
      | Constant x ->
          return (Cvar.constant (Field.inv x))
      | _ ->
          with_label label
            (let open Let_syntax in
            let%bind x_inv =
              exists Typ.field
                ~compute:
                  As_prover.(
                    map (read_var x) ~f:(fun x ->
                        if Field.(equal zero x) then Field.zero
                        else Backend.Field.inv x ))
            in
            let%map () =
              assert_r1cs ~label:"field_inverse" x x_inv
                (Cvar.constant Field.one)
            in
            x_inv)

    let div ?(label = "Checked.div") (x : Cvar.t) (y : Cvar.t) =
      match (x, y) with
      | Constant x, Constant y ->
          return (Cvar.constant (Field.( / ) x y))
      | _ ->
          with_label label
            (let open Let_syntax in
            let%bind y_inv = inv y in
            mul x y_inv)

    let%snarkydef_ if_ (b : Cvar.t Boolean.t) ~(then_ : Cvar.t) ~(else_ : Cvar.t)
        =
      let open Let_syntax in
      (* r = e + b (t - e)
         r - e = b (t - e)
      *)
      let b = (b :> Cvar.t) in
      match b with
      | Constant b ->
          if Field.(equal b one) then return then_ else return else_
      | _ -> (
          match (then_, else_) with
          | Constant t, Constant e ->
              return Cvar.((t * b) + (e * (constant Field0.one - b)))
          | _, _ ->
              let%bind r =
                exists Typ.field
                  ~compute:
                    (let open As_prover in
                    let open Let_syntax in
                    let%bind b = read_var b in
                    read Typ.field
                      (if Field.equal b Field.one then then_ else else_))
              in
              let%map () =
                assert_r1cs b Cvar.(then_ - else_) Cvar.(r - else_)
              in
              r )

    let%snarkydef_ assert_non_zero (v : Cvar.t) =
      let open Let_syntax in
      let%map _ = inv v in
      ()
}
*/

//
// Our Traits
//

impl<F> SnarkyType<F> for CVar<F>
where
    F: PrimeField,
{
    type Auxiliary = ();

    type OutOfCircuit = F;

    const SIZE_IN_FIELD_ELEMENTS: usize = 1;

    fn to_cvars(&self) -> (Vec<CVar<F>>, Self::Auxiliary) {
        (vec![self.clone()], ())
    }

    fn from_cvars_unsafe(cvars: Vec<CVar<F>>, _aux: Self::Auxiliary) -> Self {
        assert_eq!(cvars.len(), 1);
        cvars[0].clone()
    }

    fn check(&self, _cs: &mut super::checked_runner::RunState<F>) {
        // do nothing
    }

    fn constraint_system_auxiliary() -> Self::Auxiliary {}

    fn value_to_field_elements(x: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary) {
        (vec![*x], ())
    }

    fn value_of_field_elements(fields: Vec<F>, _aux: Self::Auxiliary) -> Self::OutOfCircuit {
        assert_eq!(fields.len(), 1);

        fields[0]
    }
}

//
// Operations
//

impl<F> Add for &CVar<F>
where
    F: PrimeField,
{
    type Output = CVar<F>;

    fn add(self, other: Self) -> Self::Output {
        match (self, other) {
            (CVar::Constant(x), y) | (y, CVar::Constant(x)) if x.is_zero() => y.clone(),
            (CVar::Constant(x), CVar::Constant(y)) => CVar::Constant(*x + y),
            (_, _) => CVar::Add(Box::new(self.clone()), Box::new(other.clone())),
        }
    }
}

impl<'a, F> Add<&'a Self> for CVar<F>
where
    F: PrimeField,
{
    type Output = CVar<F>;

    fn add(self, other: &Self) -> Self::Output {
        (&self).add(other)
    }
}

impl<F> Add<CVar<F>> for &CVar<F>
where
    F: PrimeField,
{
    type Output = CVar<F>;

    fn add(self, other: CVar<F>) -> Self::Output {
        self.add(&other)
    }
}

impl<F> Sub for &CVar<F>
where
    F: PrimeField,
{
    type Output = CVar<F>;

    fn sub(self, other: Self) -> Self::Output {
        match (self, other) {
            (CVar::Constant(x), CVar::Constant(y)) => CVar::Constant(*x - y),
            // TODO: why not just create a Sub variant?
            _ => self.add(&other.scale(-F::one())),
        }
    }
}

impl<'a, F> Sub<&'a CVar<F>> for CVar<F>
where
    F: PrimeField,
{
    type Output = CVar<F>;

    fn sub(self, other: &Self) -> Self::Output {
        (&self).sub(other)
    }
}

impl<F> Sub<CVar<F>> for &CVar<F>
where
    F: PrimeField,
{
    type Output = CVar<F>;

    fn sub(self, other: CVar<F>) -> Self::Output {
        self.sub(&other)
    }
}

impl<F> Neg for &CVar<F>
where
    F: PrimeField,
{
    type Output = CVar<F>;

    fn neg(self) -> Self::Output {
        self.scale(-F::one())
    }
}
