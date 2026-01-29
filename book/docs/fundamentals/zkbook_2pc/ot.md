# Oblivious Transfer

Oblivious transfer (OT) protocol is an essential tool in cryptography that
provides a wide range of applications in secure multi-party computation. The OT
protocol has different variants such as $\small 1$-out-of-$\small 2$,
$\small 1$-out-of-$\small n$ and $\small k$-out-of-$\small n$. Here we only
focus on $\small 1$-out-of-$\small 2$.

An OT protocol involves two parties: the sender and the receiver. The sender has
$\small 2$ strings, whereas the receiver has a chosen bit. After the execution
of this OT protocol, the receiver obtains one of the strings according to the
chosen bit, but no information of the other string. Then sender get no
information of the chosen bit.

```text
                    Sender                               Receiver

                                      +----------+
                    (x_0,x_1) ------->|          |<------ b
                                      | OT Prot. |
                                      |          |-------> x_b
                                      +----------+
```

Due to a result of Impagliazzo and Rudich in
[this paper](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.14.6170&rep=rep1&type=pdf),
it is very unlikely that OT is possible without the use of public-key
cryptography. However, OT can be efficiently extended. That is, starting with a
small number of base OTs, one could create many more OTs with only symmetric
primitives.

The seminal work of
[IKNP03](https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf)
presented a very efficient protocol for extending OTs, requiring only black-box
use of symmetric primitives and $\lambda$ base OTs, where $\lambda$ is the
security parameter. This doc focuses on the family of protocols inspired by
IKNP.
