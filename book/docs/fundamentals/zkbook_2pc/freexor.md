# Free XOR

The Free-XOR optimization significantly improves the efficiency of garbled
circuit. The garbler and evaluator could handle $\xor$ gates for free! The
method is given in
[KS08](http://www.cs.toronto.edu/~vlad/papers/XOR_ICALP08.pdf).

- The garbler chooses a global uniformly random string $\Delta$ with
  $\lsb(\Delta) = 1$.

- For any $\xor$ gate with input wires $a,b$ and output wire $c$, the garbler
  chooses uniformly random labels $X_a$ and $X_b$.

- Let $X_a$ and $X_a\oplus \Delta$ denote the 0 label and 1 label for input wire
  $a$, respectively. Similarly for wire $b$.

- Let $X_a\oplus X_b$ and $X_a\oplus X_b\oplus \Delta$ denote the 0 label and 1
  label for input wire $c$, respectively.

- The garbler does not need to send garbled gate for each $\xor$ gate. The
  evaluator locally $\xor$s the input labels of $\xor$ gate to gets the output
  label. This is correct because given a $\xor$ gate, the label table could be
  as follows.

|        $a$         |        $b$         |             $c$              |
| :----------------: | :----------------: | :--------------------------: |
|       $X_a$        |       $X_b$        |       $X_a\oplus X_b$        |
|       $X_a$        | $X_b\oplus \Delta$ | $X_a\oplus X_b\oplus \Delta$ |
| $X_a\oplus \Delta$ |       $X_b$        | $X_a\oplus X_b\oplus \Delta$ |
| $X_a\oplus \Delta$ | $X_b\oplus \Delta$ |       $X_a\oplus X_b$        |

Here are some remarks of the Free-XOR optimization.

- Free XOR is compatible with the point-and-permute optimization because
  $\lsb(\Delta) = 1$.

- The garbler should keep $\Delta$ private all the time for security reasons.

- Garbling $\and$ gate is the same as before except that all the labels are of
  the form $(X,X\oplus \Delta)$ for uniformly random $X$.
