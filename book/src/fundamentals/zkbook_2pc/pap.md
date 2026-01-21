# Point and Permute

As described in the last subsection, the evaluator has to decrypt all the four
ciphertexts of all the garbled gates, and extracts the valid label. This trial
decryption results in 4 decryption operations and ciphertext expansion.

The point-and-permute optimization of garbled circuit in
[BMR90](https://www.cs.ucdavis.edu/~rogaway/papers/bmr90) only needs 1
decryption and no ciphertext expansion. It works as follows.

- For the two random labels of each wire, the garbler assigns uniformly random
  `color` bits to them. For example for the wire $a$, the garbler chooses
  uniformly random labels $X_a^0,X_a^1$, and then sets
  $\lsb(X_a^1) = 1\oplus\lsb(X_a^0)$. Note that the random `color` bits are
  independent of the truth bits.

- Then the garbled gate becomes the following. Suppose the relation of the
  labels and `color` bits are $(X_a^0,X_a^1)\leftrightarrow(0,1)$,
  $(X_b^0,X_b^1)\leftrightarrow(1,0)$, $(X_c^0,X_c^1)\leftrightarrow(0,1)$

| Color Bits $(a,b,c)$  |        Garbled Gate         |
| :-------------------: | :-------------------------: |
| $(\zero,\one,\zero)$  | $\enc_{X_a^0,X_b^0}(X_c^0)$ |
| $(\zero,\zero,\zero)$ | $\enc_{X_a^0,X_b^1}(X_c^0)$ |
|  $(\one,\one,\zero)$  | $\enc_{X_a^1,X_b^0}(X_c^0)$ |
|  $(\one,\zero,\one)$  | $\enc_{X_a^1,X_b^1}(X_c^1)$ |

- Reorder the 4 ciphertexts canonically by the color bits of the input labels as
  follows.

| Color Bits $(a,b,c)$  |        Garbled Gate         |
| :-------------------: | :-------------------------: |
| $(\zero,\zero,\zero)$ | $\enc_{X_a^0,X_b^1}(X_c^0)$ |
| $(\zero,\one,\zero)$  | $\enc_{X_a^0,X_b^0}(X_c^0)$ |
|  $(\one,\zero,\one)$  | $\enc_{X_a^1,X_b^1}(X_c^1)$ |
|  $(\one,\one,\zero)$  | $\enc_{X_a^1,X_b^0}(X_c^0)$ |

- When the evaluator gets the input label, say $X_a^1,X_b^1$, the evaluator
  first extracts the `color` bits $(\lsb(X_a^1),\lsb(X_b^1)) = (\one,\zero)$ and
  decrypts the corresponding ciphertext (the third one in the above example) to
  get an output label.

## Encryption Instantiation

The encryption algorithm is instantiated with hash function (modeled as random
oracle) and one-time pad. The hash function could be truncated $\sha$. The
garbled gate is then as follows.

| Color Bits $(a,b,c)$  |          Garbled Gate          |
| :-------------------: | :----------------------------: |
| $(\zero,\zero,\zero)$ | $\sH(X_a^0,X_b^1)\oplus X_c^0$ |
| $(\zero,\one,\zero)$  | $\sH(X_a^0,X_b^0)\oplus X_c^0$ |
|  $(\one,\zero,\one)$  | $\sH(X_a^1,X_b^1)\oplus X_c^1$ |
|  $(\one,\one,\zero)$  | $\sH(X_a^1,X_b^0)\oplus X_c^0$ |

For security and efficiency reasons, one usually uses tweakable hash functions:
$\sH(\mathsf{tweak},\cdot)$, where $\mathsf{tweak}$ is public and unique for
different groups of calls to $\sH$. E.g., $\mathsf{tweak}$ could be the gate
identifier. Then the garbled gate is as follows. The optimization of tweakable
hash functions is given in following subsections.

| Color Bits $(a,b,c)$  |            Garbled Gate             |
| :-------------------: | :---------------------------------: |
| $(\zero,\zero,\zero)$ | $\sH(\gid,X_a^0,X_b^1)\oplus X_c^0$ |
| $(\zero,\one,\zero)$  | $\sH(\gid,X_a^0,X_b^0)\oplus X_c^0$ |
|  $(\one,\zero,\one)$  | $\sH(\gid,X_a^1,X_b^1)\oplus X_c^1$ |
|  $(\one,\one,\zero)$  | $\sH(\gid,X_a^1,X_b^0)\oplus X_c^0$ |
