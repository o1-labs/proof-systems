# Basics

# Basics

[Garbled circuit](https://en.wikipedia.org/wiki/Garbled_circuit) is a core
building block of two-party computation. The invention of garbled circuit was
credited to Andrew Yao, with plenty of optimizations the state-of-the-art
protocols are extremely efficient. This subsection will first introduce the
basic idea of garbled circuit.

Garbled circuit involves two parties: the garbler and the evaluator. The garbler
takes as input the circuit and the inputs, generates the garbled circuit and
encoded inputs. The evaluator takes as input the garbled circuit and encoded
inputs, evaluates the garbled circuit and decodes the result into outputs.

The security of garbled circuit ensures that the evaluator only gets the outputs
without any additional information.

Given a circuit and related inputs, the garbler handles the circuit as follows.

- For each gate in the circuit $\sC$, the garbler writes down the truth table of
  this gate. Taking an $\and$ gate for example. The truth table is as follows.
  Note that for different $\and$ gates, the wires $a,b,c$ may be different.

| $a$ | $b$ | $c$ |
| --- | --- | --- |
| $0$ | $0$ | $0$ |
| $0$ | $1$ | $0$ |
| $1$ | $0$ | $0$ |
| $1$ | $1$ | $1$ |

- The garbler chooses two uniformly random $128$-bit strings for each wire. We
  call these strings the truth labels. Label $0$ represents the value $0$ and
  label $1$ represents the value $1$. The garbler replaces the truth table with
  the following label table.

| $a$     | $b$     | $c$     |
| ------- | ------- | ------- |
| $X_a^0$ | $X_b^0$ | $X_c^0$ |
| $X_a^0$ | $X_b^1$ | $X_c^0$ |
| $X_a^1$ | $X_b^0$ | $X_c^0$ |
| $X_a^1$ | $X_b^1$ | $X_c^1$ |

- The garbler turns this label table into a garbled gate by encrypting the $c$
  labels using a symmetric double-key cipher with $a,b$ labels as the keys. The
  garbler randomly permutes the ciphertexts to break the relation between the
  label and value.

| Garbled Gate                |
| --------------------------- |
| $\enc_{X_a^0,X_b^0}(X_c^0)$ |
| $\enc_{X_a^0,X_b^1}(X_c^0)$ |
| $\enc_{X_a^1,X_b^0}(X_c^0)$ |
| $\enc_{X_a^1,X_b^1}(X_c^1)$ |

- The garbled circuit $\gc(\sC)$ consists of all garbled gates according to the
  circuit.

- Let $\sI = \sI_0\|\cdots\|\sI_k$ be the input, where $\sI_i\in\bit$, let
  $w_0,...,w_k$ be the wires of the input. The garbler sends
  $\{X_{w_i}^{\sI_i}\}_{i\in[k]}$ and $\gc(\sC)$ to the evaluator. The garbler
  also reveals the relation of the output labels and the truth values. For
  example, for each output wire, the label is chosen by setting the least
  significant bit to be the truth value.

Given the circuit $\sC$, the garbled circuit $\gc(\sC)$ and the encoded inputs
$\{X_{w_i}^{\sI_i}\}_{i\in[k]}$, the evaluator does the following.

- Uses the encoded inputs as keys, the evaluator goes through all the garbled
  gates one by one and tries to decrypt all the four ciphertexts according to
  the circuit.

- The encryption scheme is carefully designed to ensure that the evaluator could
  only decrypt to one valid message. For example, the $c$ label is encrypted by
  padding $0^{40}$, and the decrypted message contains $0^{40}$ is considered to
  be valid.

- After the evaluator gets all the labels of the output wires, he/she extracts
  the output value. For example, just take the least significant bit of the
  label.

Note that the above description of garbled circuit is very inefficient, the
following subsections will introduce optimizations to improve it.
