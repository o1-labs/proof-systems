# Half Gate

The Half-Gate optimization further reduces the number of ciphertexts from $3$ to
$2$. This is also the protocol used in zkOracles, and more details of this
algorithm will be given in this subsection. The algorithm is presented in the
[ZRE15](https://eprint.iacr.org/2014/756.pdf) paper.

We first describe the basic idea behind half-gate garbling. Let's say we want to
compute the gate $a\wedge b = c$. With the Free-XOR optimization, let
$(X_a,X_a\oplus \Delta)$ and $(X_b,X_b\oplus\Delta)$ denote the input wire
labels to this gate, and $(X_c,X_c\oplus \Delta)$ denote the output wire labels,
with $X_a,X_b,X_c$ each encoding $0$.

Half-gate garbling contains two case: when the garbler knows one of the inputs,
and when the evaluator knows one of the inputs.

**Garbler half-gate**. Considering the case of an $\and$ gate $a\wedge b = c$,
where $a,b$ are intermediate wires in the circuit and the garbler somehow knows
in advance what the value $a$ will be.

When $a = 0$, the garbler will garble a unary gate that always outputs $0$. The
label table is as follows.

|        $b$         |  $c$  |
| :----------------: | :---: |
|       $X_b$        | $X_c$ |
| $X_b\oplus \Delta$ | $X_c$ |

Then the garbler generates two ciphertexts: $$\sH(X_b)\oplus X_c$$
$$\sH(X_b\oplus\Delta)\oplus X_c$$

When $a = 1$, the garbler will garble a unary identity gate. The label table is
as follows.

|        $b$         |        $c$         |
| :----------------: | :----------------: |
|       $X_b$        |       $X_c$        |
| $X_b\oplus \Delta$ | $X_c\oplus \Delta$ |

Then the garbler generates two ciphertexts:

$$\sH(X_b)\oplus X_c$$ $$\sH(X_b\oplus\Delta)\oplus X_c\oplus \Delta$$

Since $a$ is known to the garbler, the two cases shown above could be unified as
follows:

$$\sH(X_b)\oplus X_c$$ $$\sH(X_b\oplus\Delta)\oplus X_c\oplus a\cdot\Delta$$

These two ciphertexts are then suitably permuted according to the `color` bits
of $X_b$. The evaluator takes a hash of its wire label for $X_b$ and decrypts
the appropriate ciphertext. If $a = 0$, he/she obtains output wire label $X_c$
in both values of $b$. If $a = 1$ the evaluator obtains either $X_c$ or
$X_c\oplus \Delta$, depending on the bit $b$. Intuitively, the evaluator will
never know both $X_b$ and $X_b\oplus\Delta$, hence the other ciphertext appears
completely random.

By applying the row-reduction optimization, we reduce the number of ciphertexts
from $2$ to $1$ as follows.
$$\sH(X_b\oplus\Delta)\oplus \sH(X_b)\oplus a\cdot\Delta$$

**Evaluator half-gate**. Considering the case of an $\and$ gate $a\wedge b = c$,
where $a,b$ are intermediate wires in the circuit and the evaluator somehow
knows the value $a$ at the time of evaluation. The evaluator can behave
differently based on the value of $a$.

When $a = 0$, the evaluator should always obtain output wire label $X_c$, then
the garbled circuit should contains the ciphertext: $$\sH(X_a)\oplus X_c$$

When $a = 1$, it is enough for the evaluator to obtain $R= X_c\oplus X_b$.
He/she can then $\xor$ $R$ with the other wire label (either $X_b$ or
$X_b\oplus \Delta$) to obtain either $X_c$ or $X_c\oplus \Delta$. Hence the
garbler should provide the ciphertext:
$$\sH(X_a\oplus\Delta)\oplus X_c\oplus X_b$$

Combining the above two case together, the garbler should provide two
ciphertexts: $$\sH(X_a)\oplus X_c$$ $$\sH(X_a\oplus\Delta)\oplus X_c\oplus X_b$$

Note that these two ciphertext do NOT have to be permuted according to the
`color` bit of $X_a$, because the evaluator already knows $a$. If $a = 0$, the
evaluator uses the wire label $X_a$ to decrypt the first ciphertext. If $a = 1$,
the evaluator uses the wire label $X_a\oplus \Delta$ to decrypt the second
ciphertext and $\xor$s the result with the wire label for $b$.

By applying the row-reduction optimization, we reduce the number of ciphertexts
from $2$ to $1$ as follows. $$\sH(X_a\oplus\Delta)\oplus \sH(X_a)\oplus X_b$$

**Two halves make a whole**. Considering the case to garble an $\and$ gate
$a\wedge b = c$, where both inputs are secret. Consider:
$$c = a \wedge b = a\wedge (r\oplus r\oplus b) = (a\wedge r)\oplus (a\wedge(r\oplus b))$$

Suppose the garbler chooses uniformly random bit $r$. In this case, the first
$\and$ gate $(a\wedge r)$ can be garbled with a garbler-half-gate. If we further
arrange for the evaluator to learn the value $r\oplus b$, then the second $\and$
gate $(a\wedge(r\oplus b))$ can be garbled with an evaluator-half-gate. Leaking
this extra bit $r\oplus b$ to the evaluator is safe, as it carries no
information about the sensitive value $b$. The remaining $\xor$ gate is free and
the total cost is $2$ ciphertexts.

Actually the evaluator could learn $r\oplus b$ without any overhead. The garbler
choose the `color` bit of the 0 label $X_b$ on wire $b$. Since that `color` bit
is chosen uniformly, it is secure to use it. Then when a particular value $b$ is
on that wire, the evaluator will hold a wire label whose `color` bit is
$b\oplus r$.

Let $X_b^0,X_b^1 = X_b^0\oplus \Delta$ be the labels for $b$, let
$p = \lsb(X_b^0)$. $p$ is the `color` bit of the wire, is a secret known only to
the garbler. When the evaluator holds a wire label for $b$ whose `color` bit is
$s$, the label is $X_b^{s\oplus p}$, corresponding to truth value $s\oplus p$.
