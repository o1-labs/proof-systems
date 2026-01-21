# Proof Systems Design Overview

Many modern proof systems (and I think all that are in use) are constructed
according to the following recipe.

1. You start out with a class of computations.

2. You devise a way to _arithmetize_ those computations. That is, to express
   your computation as a statement about polynomials.

   More specifically, you describe what is often called an "algebraic
   interactive oracle proof" (AIOP) that encodes your computation. An AIOP is a
   protocol describing an interaction between a prover and a verifier, in which
   the prover sends the verifier some "polynomial oracles" (basically a black
   box function that given a point evaluates a polynomial at that point), the
   verifier sends the prover random challenges, and at the end, the verifier
   queries the prover's polynomials at points of its choosing and makes a
   decision as to whether it has been satisfied by the proof.

3. An AIOP is an imagined interaction between parties. It is an abstract
   description of the protocol that will be "compiled" into a SNARK. There are
   several "non-realistic" aspects about it. One is that the prover sends the
   verifier black-box polynomials that the verifier can evaluate. These
   polynomials have degree comparable to the size of the computation being
   verified. If we implemented these "polynomial oracles" by having the prover
   really send the $O(n)$ size polynomials (say by sending all their
   coefficients), then we would not have a zk-SNARK at all, since the verifier
   would have to read this linearly sized polynomial so we would lose
   succinctness, and the polynomials would not be black-box functions, so we may
   lose zero-knowledge.

   Instead, when we concretely instantiate the AIOP, we have the prover send
   constant-sized, hiding _polynomial commitments_. Then, in the phase of the
   AIOP where the verifier queries the polynomials, the prover sends an _opening
   proof_ for the polynomial commitments which the verifier can check, thus
   simulating the activity of evaluating the prover's polynomials on your own.

   So this is the next step of making a SNARK: instantiating the AIOP with a
   polynomial commitment scheme of one's choosing. There are several choices
   here and these affect the properties of the SNARK you are constructing, as
   the SNARK will inherit efficiency and setup properties of the polynomial
   commitment scheme used.

4. An AIOP describes an interactive protocol between the verifier and the
   prover. In reality, typically, we also want our proofs to be non-interactive.

   This is accomplished by what is called the [Fiat--Shamir transformation]().
   The basic idea is this: all that the verifier is doing is sampling random
   values to send to the prover. Instead, to generate a "random" value, the
   prover simulates the verifier by hashing its messages. The resulting hash is
   used as the "random" challenge.

   At this point we have a fully non-interactive proof. Let's review our steps.
   1. Start with a computation.

   2. Translate the computation into a statement about polynomials and design a
      corresponding AIOP.

   3. Compile the AIOP into an interactive protocol by having the prover send
      hiding polynomial commitments instead of polynomial oracles.

   4. Get rid of the verifier-interaction by replacing it with a hash function.
      I.e., apply the Fiat--Shamir transform.
