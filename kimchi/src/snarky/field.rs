// TODO: I think I can delete this code safely...

use ark_ff::{Field, PrimeField, SquareRootField};

use super::{
    boolean::Boolean,
    checked_runner::{RunState, TypeCreation},
    cvar::CVar,
    traits::{SnarkyType, SnarkyType2},
};

//
// Field stuff
//

fn is_square<F: Field>(ff: F) -> bool {
    let euler = -1 / 2;
    ff.pow(euler) == F::one()
}

/// Finds `q` such that there is no `x^2 = q mod p`.
fn quadratic_nonresidue<F: Field>() {
    for ii in 2.. {
        let mut x = F::from(ii);

        if !is_square(&x) {
            return x;
        }
        x += F::one();
    }
}

//
// FieldVar
//

pub struct FieldVar<F: PrimeField>(CVar<F>);

//
// Traits
//

impl<F> SnarkyType2<F> for FieldVar<F>
where
    F: PrimeField,
{
    type OutOfCircuit = F;

    type Auxiliary = ();

    const SIZE_IN_FIELD_ELEMENTS: usize = 1;

    fn check(&self, cs: &mut RunState<F>) {
        todo!()
    }

    fn to_cvars(&self) -> (Vec<CVar<F>>, Self::Auxiliary) {
        (vec![self.0], ())
    }

    fn from_cvars_unsafe(cvars: Vec<CVar<F>>, aux: Self::Auxiliary) -> Self {
        assert_eq!(cvars.len(), 1);
        (Self(cvars[0]), ())
    }

    fn deserialize(&self) -> (Self::OutOfCircuit, Self::Auxiliary) {
        todo!()
    }

    fn serialize(out_of_circuit: Self::OutOfCircuit, aux: Self::Auxiliary) -> Self {
        todo!()
    }
}

impl<F> SnarkyType<F> for FieldVar<F>
where
    F: PrimeField,
{
    fn value_to_field_elements(x: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary) {
        todo!()
    }

    fn value_of_field_elements(x: (Vec<F>, Self::Auxiliary)) -> Self::OutOfCircuit {
        todo!()
    }

    fn constraint_system_auxiliary() -> Self::Auxiliary {
        todo!()
    }
}

impl<F> FieldVar<F>
where
    F: PrimeField,
{
    pub fn sqrt(&self, state: &mut RunState<F>) -> Self
    where
        F: SquareRootField,
    {
        match &self.0 {
            CVar::Constant(x) => CVar::Constant(x.sqrt().unwrap),
            _ => {
                let y: FieldVar<F> = state.exists(
                    TypeCreation::Checked,
                    Box::new(|env| {
                        let x = env.read_var(self);
                        x.sqrt().unwrap()
                    }),
                );
                state.assert_square(y, self);
                y
            }
        }
    }

    /** The trick here is the following.

       Let beta be a known non-square.

       x is not a square iff beta*x is a square

       So we guess the result [is_square] and y a sqrt of one of {x, beta*x} and assert

       y * y = is_square * x + (1 - is_square) * (beta * x)

       which, letting B = beta*x holds iff

       y * y
       = is_square * x + B - is_square * B
       = is_square * (x - B) + B
    */
    pub fn sqrt_check(&self, state: &mut RunState<F>) {
        let is_square: Boolean<F> = state.exists(
            TypeCreation::Checked,
            Box::new(|env| {
                let x: F = env.read_var(&self.0);
                is_square(x)
            }),
        );
        let y: FieldVar<F> = state.exists(
            TypeCreation::Checked,
            Box::new(|env| {
                let is_square = env.read_var(&is_square.0);
                todo!();
            }),
        );

        todo!();
    }
    /*
    let sqrt_check x =
      let open Checked in
      let open Let_syntax in
      let%bind is_square =
        exists
          ~compute:As_prover.(map (read_var x) ~f:Field.is_square)
          Boolean.typ
      in
      let%bind y =
        exists typ
          ~compute:
            As_prover.(
              Let_syntax.(
                let%map is_square = read Boolean.typ is_square
                and x = read_var x in
                if is_square then Field.sqrt x
                else Field.(sqrt (Lazy.force quadratic_nonresidue * x))))
      in
      let b = scale x (Lazy.force quadratic_nonresidue) in
      let%bind t = mul (is_square :> Var.t) (x - b) in
      let%map () = assert_square y (t + b) in
      (y, is_square)
       */
}

/*

    (* The trick here is the following.

       Let beta be a known non-square.

       x is not a square iff beta*x is a square

       So we guess the result [is_square] and y a sqrt of one of {x, beta*x} and assert

       y * y = is_square * x + (1 - is_square) * (beta * x)

       which, letting B = beta*x holds iff

       y * y
       = is_square * x + B - is_square * B
       = is_square * (x - B) + B
    *)
    let sqrt_check x =
      let open Checked in
      let open Let_syntax in
      let%bind is_square =
        exists
          ~compute:As_prover.(map (read_var x) ~f:Field.is_square)
          Boolean.typ
      in
      let%bind y =
        exists typ
          ~compute:
            As_prover.(
              Let_syntax.(
                let%map is_square = read Boolean.typ is_square
                and x = read_var x in
                if is_square then Field.sqrt x
                else Field.(sqrt (Lazy.force quadratic_nonresidue * x))))
      in
      let b = scale x (Lazy.force quadratic_nonresidue) in
      let%bind t = mul (is_square :> Var.t) (x - b) in
      let%map () = assert_square y (t + b) in
      (y, is_square)

    let is_square x =
      let open Checked.Let_syntax in
      let%map _, b = sqrt_check x in
      b

    let%test_unit "is_square" =
      let x = Field.random () in
      let typf = Typ.field in
      let x2 = Field.square x in
      assert (Field.(equal (x * x) x2)) ;
      let run elt =
        let answer =
          run_and_check
            (Checked.map
               ~f:(As_prover.read Checked.Boolean.typ)
               Checked.(
                 Let_syntax.(
                   let%bind x = exists typf ~compute:(As_prover.return elt) in
                   is_square x)) )
          |> Or_error.ok_exn
        in
        answer
      in
      assert (run x2) ;
      assert (not (run (Field.mul (Lazy.force quadratic_nonresidue) x2)))

    let choose_preimage_var = Checked.choose_preimage

    type comparison_result =
      { less : Checked.Boolean.var; less_or_equal : Checked.Boolean.var }

    let if_ = Checked.if_

    let compare ~bit_length a b =
      (* Overview of the logic:
         let n = bit_length
         We have 0 <= a < 2^n, 0 <= b < 2^n, and so
           -2^n < b - a < 2^n
         If (b - a) >= 0, then
           2^n <= 2^n + b - a < 2^{n+1},
         and so the n-th bit must be set.
         If (b - a) < 0 then
           0 < 2^n + b - a < 2^n
         and so the n-th bit must not be set.
         Thus, we can use the n-th bit of 2^n + b - a to determine whether
           (b - a) >= 0 <-> a <= b.

         We also need that the maximum value
           2^n + (2^n - 1) - 0 = 2^{n+1} - 1
         fits inside the field, so for the max field element f,
           2^{n+1} - 1 <= f -> n+1 <= log2(f) = size_in_bits - 1
      *)
      assert (Int.(bit_length <= size_in_bits - 2)) ;
      let open Checked in
      let open Let_syntax in
      [%with_label_ "compare"]
        (let alpha_packed = Cvar.(constant (two_to_the bit_length) + b - a) in
         let%bind alpha = unpack alpha_packed ~length:Int.(bit_length + 1) in
         let prefix, less_or_equal =
           match Core_kernel.List.split_n alpha bit_length with
           | p, [ l ] ->
               (p, l)
           | _ ->
               failwith "compare: Invalid alpha"
         in
         let%bind not_all_zeros = Boolean.any prefix in
         let%map less = Boolean.(less_or_equal && not_all_zeros) in
         { less; less_or_equal } )

    module Assert = struct
      let lt ~bit_length x y =
        let open Checked in
        let open Let_syntax in
        let%bind { less; _ } = compare ~bit_length x y in
        Boolean.Assert.is_true less

      let lte ~bit_length x y =
        let open Checked in
        let open Let_syntax in
        let%bind { less_or_equal; _ } = compare ~bit_length x y in
        Boolean.Assert.is_true less_or_equal

      let gt ~bit_length x y = lt ~bit_length y x

      let gte ~bit_length x y = lte ~bit_length y x

      let non_zero = Checked.assert_non_zero

      let equal x y = Checked.assert_equal ~label:"Checked.Assert.equal" x y

      let not_equal (x : t) (y : t) =
        Checked.with_label "Checked.Assert.not_equal" (non_zero (sub x y))
    end

    let lt_bitstring_value =
      let module Boolean = Checked.Boolean in
      let module Expr = struct
        module Binary = struct
          type 'a t = Lit of 'a | And of 'a * 'a t | Or of 'a * 'a t
        end

        module Nary = struct
          type 'a t = Lit of 'a | And of 'a t list | Or of 'a t list

          let rec of_binary : 'a Binary.t -> 'a t = function
            | Lit x ->
                Lit x
            | And (x, And (y, t)) ->
                And [ Lit x; Lit y; of_binary t ]
            | Or (x, Or (y, t)) ->
                Or [ Lit x; Lit y; of_binary t ]
            | And (x, t) ->
                And [ Lit x; of_binary t ]
            | Or (x, t) ->
                Or [ Lit x; of_binary t ]

          let rec eval =
            let open Checked.Let_syntax in
            function
            | Lit x ->
                return x
            | And xs ->
                Checked.List.map xs ~f:eval >>= Boolean.all
            | Or xs ->
                Checked.List.map xs ~f:eval >>= Boolean.any
        end
      end in
      let rec lt_binary xs ys : Boolean.var Expr.Binary.t =
        match (xs, ys) with
        | [], [] ->
            Lit Boolean.false_
        | [ _x ], [ false ] ->
            Lit Boolean.false_
        | [ x ], [ true ] ->
            Lit (Boolean.not x)
        | [ x1; _x2 ], [ true; false ] ->
            Lit (Boolean.not x1)
        | [ _x1; _x2 ], [ false; false ] ->
            Lit Boolean.false_
        | x :: xs, false :: ys ->
            And (Boolean.not x, lt_binary xs ys)
        | x :: xs, true :: ys ->
            Or (Boolean.not x, lt_binary xs ys)
        | _ :: _, [] | [], _ :: _ ->
            failwith "lt_bitstring_value: Got unequal length strings"
      in
      fun (xs : Boolean.var Bitstring_lib.Bitstring.Msb_first.t)
          (ys : bool Bitstring_lib.Bitstring.Msb_first.t) ->
        let open Expr.Nary in
        eval
          (of_binary (lt_binary (xs :> Boolean.var list) (ys :> bool list)))

    let field_size_bits =
      List.init Field.size_in_bits ~f:(fun i ->
          Z.testbit
            (Bignum_bigint.to_zarith_bigint Field.size)
            Stdlib.(Field.size_in_bits - 1 - i) )
      |> Bitstring_lib.Bitstring.Msb_first.of_list

    let unpack_full x =
      let module Bitstring = Bitstring_lib.Bitstring in
      let open Checked.Let_syntax in
      let%bind res =
        choose_preimage_var x ~length:Field.size_in_bits
        >>| Bitstring.Lsb_first.of_list
      in
      let%map () =
        lt_bitstring_value
          (Bitstring.Msb_first.of_lsb_first res)
          field_size_bits
        >>= Checked.Boolean.Assert.is_true
      in
      res

    let parity ?length x =
      let open Checked in
      let unpack =
        let unpack_full x =
          unpack_full x >>| Bitstring_lib.Bitstring.Lsb_first.to_list
        in
        match length with
        | None ->
            unpack_full
        | Some length ->
            let length = Int.min length Field.size_in_bits in
            if Int.equal length Field.size_in_bits then unpack_full
            else choose_preimage_var ~length
      in
      unpack x >>| Base.List.hd_exn
  end
end
*/
