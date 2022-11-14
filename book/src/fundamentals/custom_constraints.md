This section explains how to design and add a custom constraint to our `proof-systems` library.

PLONK is an AIOP. That is, it is a protocol in which the prover sends polynomials as messages and the verifier sends random challenges, and then evaluates the prover's polynomials and performs some final checks on the outputs.

PLONK is very flexible. It can be customized with constraints specific to computations of interest. For example, in Mina, we use a PLONK configuration called kimchi that has custom constraints for poseidon hashing, doing elliptic curve operations, and more.

A "PLONK configuration" specifies
- The set of types of constraints that you would like to be able to enforce. We will describe below how these types of constraints are specified.
- A number of "eq-able" columns `W`
- A number of "advice" columns `A`

Under such configuration, a circuit is specified by
- A number of rows `n`
- A vector `cs` of constraint-types of length `n`. I.e., a vector that specifies, for each row, which types of constraints should be enforced on that row.
- A vector `eqs : Vec<(Position, Position)>` of equalities to enforce, where `struct Position { row: usize, column: usize }`. E.g., if the pair `(Position { row: 0, col: 8 }, Position { row: 10, col: 2 })` is in `eqs`, then the circuit is saying the entries in those two positions should be equal, or in other words that they refer to the same value. This is where the distinction between "eq-able" and "advice" columns comes in. The `column` field of a position in the `eqs` array can only refer to one of the first `W` columns. Equalities cannot be enforced on entries in the `A` columns after that.

Then, given such a circuit, PLONK lets you produce proofs for the statement

> I know `W + A` "column vectors" of field elements `vs: [Vec<F>; W + A]` such that for each row index `i < n`, the constraint of type `cs[i]` holds on the values `[vs[0][i], ..., vs[W+A - 1][i], vs[0][i+1], ..., vs[W+A - 1][i+1]` and all the equalities in `eqs` hold. I.e., for `(p1, p2)` in `eqs` we have `vs[p1.col][p1.row] == vs[p2.col][p2.row]`. So, a constraint can check the values in two adjacent rows.

## Specifying a constraint

Mathematically speaking, a constraint is a multivariate polynomial over the variables $c_{\mathsf{Curr},i}, \dots, v_{\mathsf{Curr}, W+A-1}, v_{\mathsf{Next}, 0}, \dots, v_{\mathsf{Next}, W+A-1}$. In other words, there is one variable corresponding to the value of each column in the "current row" and one variable correspond to the value of each column in the "next row".

In Rust, $v_{r, i}$ is written `E::cell(Column::Witness(i), r)`. So, for example, the variable $v_{\mathsf{Next}, 3}$ is written
`E::cell(Column::Witness(3), CurrOrNext::Next)`.



    let w = |i| v(Column::Witness(i));
Let's 

## Defining a PLONK configuration

The art in proof systems comes from knowing how to design a PLONK configuration to ensure maximal efficiency for the sorts of computations you are trying to prove. That is, how to choose the numbers of columns `W` and `A`, and how to define the set of constraint types.

Let's describe the trade-offs involved here.

The majority of the proving time for the PLONK prover is in
- committing to the `W + A` column polynomials, which have length equal to the number of rows `n`
- committing to the "permutation accumulator polynomial, which has length `n`.
- committing to the quotient polynomial, which reduces to computing `max(k, W)` MSMs of size `n`, where `k` is the max degree of a constraint.
- performing the commitment opening proof, which is mostly dependent on the number of rows `n`.

So all in all, the proving time is approximately equal to the time to perform `W + A + 1 + max(k - 1, W)` MSMs of size `n`, plus the cost of an opening proof for polynomials of degree `n - 1`.

and maybe
- computing the combined constraint polynomial, which has degree `k * n` where `k` is the maximum degree of a constraint

- Increasing `W` and `A` increase proof size, and they potentially impact the prover-time as the prover must compute polynomial commitments to each column, and computing a polynomial commitment corresponds to doing one MSM (multi-scalar multiplication, also called a multi-exponentiation.)

  However, often increasing the number of columns allows you to decrease the number of rows required for a given computation. For example, if you can perform one Poseidon hash in 36 rows with 5 total columns, then you can also perform it in 12 (= 36 / 3) rows with 15 (= 5 * 3) total columns.

  **Decreasing the number of rows (even while keeping the total number of table entries the same) is desirable because it reduces the cost of the polynomial commitment opening proof, which is dominated by a factor linear in the number of rows, and barely depends on the the number of columns.**

  Increasing the number of columns also increases verifier time, as the verifier must perform one scalar-multiplication and one hash per column. Proof length is also affected by a larger number of columns, as more polynomials need to be committed and sent along to the verifier.

There is typically some interplay between these 
