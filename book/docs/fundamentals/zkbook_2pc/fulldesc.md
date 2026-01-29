# Full Description

**Garbling**. The garbling algorithm $\mathsf{Garble}(\sC)$ is described as
follows.

- Let $\mathsf{CircuitInputs}(\sC)$, $\mathsf{CircuitOutputs}(\sC)$ be the set
  of input and output wires of $\sC$, respectively. Given a non-input wire $i$,
  let $(a,b)\leftarrow\mathsf{InputWires}(\sC,i)$ denote the two input wires
  $a,b$ of $i$ associated to an $\and$ or $\xor$ gate. Let
  $a\leftarrow\mathsf{InputsWires}(\sC,i)$ denote the input wire $a$ of $i$
  associated to an $\inv$ gate. The garbler maintains three sets $E$,$D$ and
  $T$. The garbler also maintains a $\counter$ initiated as $0$.

- Choose a secret global 128-bit string $\Delta$ uniformly, and set
  $\lsb(\Delta) = 1$. Let $P = X\oplus \Delta$ be the label of public bit $1$,
  where $X$ is chosen uniformly at random. Note that $P$ will be sent to the
  evaluator.

- For $i\in\mathsf{CircuitInputs}(\sC)$, do the following.
  - Choose $128$-bit $X_i^0$ uniformly at random, and set
    $X_i^1 = X_i^0\oplus \Delta$.
  - Let $e_i = X_i^0$ and insert it to $E$.

- For any non-input wire $i$, do the following.
  - If the gate associated to $i$ is a $\xor$ gate.
    - Let $(a,b)\leftarrow\mathsf{GateInputs}(\sC,i)$.
    - Compute $X_i^0 = X_a^0\oplus X_b^0$ and $X_i^1 = X_i^0\oplus \Delta$.
  - If the gate associated to $i$ is an $\inv$ gate.
    - Let $a\leftarrow\mathsf{GateInputs}(\sC,i)$,
    - Compute $X_i^0 = X_a^0\oplus P$ and $X_i^1 = X_i^0\oplus \Delta$.
  - If the gate associated to $i$ is an $\and$ gate.
    - let $(a,b)\leftarrow\mathsf{GateInputs}(\sC,i)$,
    - Let $p_a = \lsb(X_a^0)$, $p_b = \lsb(X_b^0)$.
    - Compute the first half gate:
    - Let
      $T_G = \sH(\counter,X_a^0)\oplus \sH(\counter,X_a^1)\oplus (p_b\cdot \Delta)$.
    - Let $X_G^0 = \sH(\counter,X_a^0)\oplus (p_a\cdot T_G)$.
    - $\counter = \counter + 1$.
    - Compute the second half gate:
    - Let $T_E = \sH(\counter,X_b^0)\oplus\sH(\counter,X_b^1)\oplus X_a^0$.
    - Let $X_E^0 = \sH(\counter,X_b^0)\oplus p_b\cdot (T_E\oplus X_a^0)$
    - Let $X_i^0 = X_G^0\oplus X_E^0$, $X_i^1 = X_i^0\oplus\Delta$ and insert
      the garbled gate $(T_G,T_E)$ to $T$.
    - $\counter = \counter + 1$.

- For $i\in\mathsf{CircuitOutputs}(\sC)$, do the following.
  - Compute $d_i = \lsb(X_i^0)$.
  - Insert $d_i$ into $D$.

- The garbler outputs $(G,E,D)$.

**Input Encoding**. Given $E = (e_1,...,e_\ell)$, the garbler encodes the input
$(x_1,...,x_\ell)\in\bit^\ell$ as follows.

- For all $1\leq i\leq \ell$, compute $X_i = e_i\oplus x_i\Delta$
- Outputs $X = (X_1,...,X_\ell)$.

**Evaluating**. The evaluating algorithm $\mathsf{Eval}(\sC)$ is described as
follows.

- The evaluator takes as input the garbled circuit $T$ and the encoded inputs
  $X$.

- The evaluator obtains the input labels $(X_1,...,X_\ell)$ from $X$ and
  initiates $\counter = 0$.

- For any non-input wire $i$, do the following.
  - If the gate associated to $i$ is a $\xor$ gate.
    - Let $(a,b)\leftarrow\mathsf{GateInputs}(\sC,i)$.
    - Compute $X_i = X_a\oplus X_b$.
  - If the gate associated to $i$ is an $\inv$ gate.
    - Let $a\leftarrow\mathsf{GateInputs}(\sC,i)$,
    - Compute $X_i = X_a\oplus P$.
  - If the gate associated to $i$ is an $\and$ gate.
    - Let $(a,b)\leftarrow\mathsf{GateInputs}(\sC,i)$,
    - Let $s_a = \lsb(X_a)$, $s_b = \lsb(X_b)$.
    - Parse $T_i$ as $(T_G,T_E)$.
    - Compute $X_G = \sH(\counter,X_a)\oplus s_a\cdot T_G$.
    - $\counter = \counter + 1$.
    - Compute $X_E = \sH(\counter, X_b)\oplus s_b(T_E\oplus X_a)$.
    - Let $X_i = X_G\oplus X_E$.

- For $i\in\mathsf{CircuitOutputs}(\sC)$, do the following.
  - Let $Y_i = X_i$.
  - Outputs $Y$, the set of $Y_i$.

**Output Decoding**. Given $Y$ and $D$, the evaluator decodes the labels into
outputs as follows.

- For any $i$, compute $y_i = d_i\oplus\lsb(Y_i)$.
- Outputs all $y_i$.
