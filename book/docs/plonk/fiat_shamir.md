# Non-Interactivity via Fiat-Shamir

So far we've talked about an interactive protocol between a prover and a
verifier. The zero-knowledge proof was also in the honest verifier
zero-knowedlge (HVZK) model, which is problematic.

In practice, we want to remove the interaction and have the prover produce a
proof by themselves, that anyone can verify.

## Public-coin protocols

public-coin protocols are protocols were the messages of the verifier are simply
random messages. This is important as our technique to transform an interactive
protocol to a non-interactive protocol works on public-coin protocols.

## Fiat-Shamir trick

The whole idea is to replace the verifier by a random oracle, which in practice
is a hash function. Note that by doing this, we remove potential leaks that can
happen when the verifier acts dishonestly.

Initially the Fiat-Shamir transformation was only applied to sigma protocols,
named after the greek letter $\Sigma$ due to its shape resembling the direction
of messages (prover sends a commit to a verifier, verifier sends a challenge to
a prover, prover sends the final proof to a verifier). A $Z$ would have made
more sense but here we are.

## Generalization of Fiat-Shamir

As our protocol has more than three moves, where every even move is a challenge
from the verifier, we need to generalize Fiat-Shamir. This is simple: every
verifier move can be replaced by a hash of the transcript (every message sent
and received so far) to obtain a challenge.

## In practice: a duplex construction as Merlin

While we use a hash function for that, a different construction called the
[duplex construction](https://keccak.team/sponge_duplex.html) is particularly
useful in such situations as they allow to continuously absorb the transcript
and produce challenges, while automatically authenticating the fact that they
produced a challenge.

[Merlin](https://merlin.cool/) is a standardization of such a construction using
the [Strobe protocol framework](https://strobe.sourceforge.io/) (a framework to
make use of a duplex construction). Note that the more recent
[Xoodyak](https://keccak.team/xoodyak.html) (part of NIST's lightweight
competition) could have been used for this as well. Note also that Mina uses
none of these standards, instead it simply uses Poseidon (see section on
poseidon).
