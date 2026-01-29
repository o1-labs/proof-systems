# Row Reduction

With the Free-XOR optimization, the bottleneck of garbled circuit is to handle
$\and$ gates. Row reduction aims to reduce the number of ciphertexts of each
garbled $\and$ gate. More specifically, it reduces $4$ ciphertexts into $3$. The
optimization is given in the
[NPS99](https://www.wisdom.weizmann.ac.il/~naor/PAPERS/nps.pdf) paper.

To be compatible with the Free-XOR optimization, the garbled $\and$ gates are of
the following form (still use the example in the point-and-permute
optimization).

| Color Bits $(a,b,c)$  |                          Garbled Gate                           |
| :-------------------: | :-------------------------------------------------------------: |
| $(\zero,\zero,\zero)$ |              $\sH(X_a,X_b\oplus \Delta)\oplus X_c$              |
| $(\zero,\one,\zero)$  |                    $\sH(X_a,X_b)\oplus X_c$                     |
|  $(\one,\zero,\one)$  | $\sH(X_a\oplus \Delta,X_b\oplus \Delta)\oplus X_c\oplus \Delta$ |
|  $(\one,\one,\zero)$  |              $\sH(X_a\oplus \Delta,X_b)\oplus X_c$              |

Since $\sH$ is modeled as a random oracle, one could set the first row of the
above garbled gate as $0$, and then we could remove that row from the garbled
gate. This means that we could choose $X_c = \sH(X_a,X_b\oplus \Delta)$.
Therefore, the garbled circuit is changed as follows.

| Color Bits $(a,b,c)$ |                                     Garbled Gate                                      |
| :------------------: | :-----------------------------------------------------------------------------------: |
| $(\zero,\one,\zero)$ |                    $\sH(X_a,X_b)\oplus \sH(X_a,X_b\oplus \Delta)$                     |
| $(\one,\zero,\one)$  | $\sH(X_a\oplus \Delta,X_b\oplus \Delta)\oplus \sH(X_a,X_b\oplus \Delta)\oplus \Delta$ |
| $(\one,\one,\zero)$  |              $\sH(X_a\oplus \Delta,X_b)\oplus \sH(X_a,X_b\oplus \Delta)$              |

The evaluator handles garbled $\and$ gates as before, except he/she directly
computes the hash function if the `color` bits are $(\zero,\zero)$.
