# zk-SNARKs

Finally we can discuss zk-SNARKs. In these notes right now I will not start with
intuitive motivations for SNARKs because I can't think of them right now, but
maybe later.

Let $f \colon A \times W \to \mathsf{Bool}$ be a program (in some yet to be
specified programming language). For $a \colon A$, zk-SNARKs let you produce
proofs for statements of the form

> I know $w \colon W$ such that $f(a, w) = \mathsf{true}$

in such a way that no information about $w$ is revealed by the proof (this is
the zero-knowledge or ZK part of them).

In other words, zk-SNARKs allow you to prove execution of programs, where you
are also allowed to hide a selected portion (i.e., the $W$ portion) of the data
involved in the computation.

We could also phrase zk-SNARKs in terms of computing functions
$f \colon A \times W \to B$, which seems more general, but actually this would
be taken care of by the previous sense where we can only use boolean-valued
functions, by proving against the function
$g \colon (A \times B) \times W \to \mathsf{Bool}$ defined by
$g((a, b), w) := b =_{?} f(a, w)$.

<!-- querolita: the succinctness property of a SNARK means a verification algorithm running in poly(lambda + |x| + log|w|) and proof length of poly(lambda + \log|w|), for lambda the security parameter, x the public input and w the private witness. Then, assuming that the number of wires (witness) is in the order of O(n) where n is the number of gates, I would say that Kimchi is indeed a SNARK expect without a constant proof length -->

SNARK stands for _Succinct Non-interactive ARguments of Knowledge_. If it also
satisfies zero-knowledge, then it is called a zk-SNARK. Preprocessing SNARKs
allow the verifier to precompute some encodings of the relation to run
independently of the instance length. Definitions of these schemes owe the
_succinctness_ property to the fact that both the verifier and the proof length
are (at most) polylogarithmic in the size of the computation (the witness
length). Recent schemes such as Plonk, go beyond that definition and provide
zkSNARKs with constant proof length. Unlike the verifier in preprocessing
SNARKs, the prover can't be faster than linear, as it has to read the circuit at
least.

## Expressing computations with "iterating over trace tables"

We will define a notion of computation (a programming language basically) for
which it is easy to construct zk-SNARKs.
