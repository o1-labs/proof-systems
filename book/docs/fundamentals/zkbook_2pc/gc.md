# Garbled Circuits

For general-purpose secure computation protocols, we often view functions as
arithmetic circuits or boolean circuits. We consider boolean circuits because
our applications involve in securely computing ciphers (e.g., AES), which
consist of massive boolean gates.

## Boolean Circuits

Boolean circuits consists of $\and$ gates ($a~\and~ b = a\wedge b$) and $\xor$
gates ($a~\xor~b = a\oplus b$). These two gates are universal and we could
represent any polynomial-size functions with them. In 2PC protocols, we also use
$\inv$ gates ($\inv(a) = 1\oplus a$) for optimization.

According to the Free-XOR optimization (see the next subsection), the $\xor$
gates and $\inv$ gates are free, then one prefers to represent a function with
more $\xor$ and $\inv$ gates, while less $\and$ gates.

For some commonly used functions (e.g., AES, SHA256), one usually uses
hand-optimized circuits for efficiency, and stores them in files. The most
popular circuit representation is the
[Bristol Fashion](https://homes.esat.kuleuven.be/~nsmart/MPC/), which is also
used in zkOracles.

The following Bristol fashion circuit is part of AES-128.

```text
36663 36919
2 128 128
1 128

2 1 128 0 33254 XOR
2 1 129 1 33255 XOR
2 1 130 2 33256 XOR
2 1 131 3 33257 XOR
2 1 132 4 33258 XOR
2 1 133 5 33259 XOR
2 1 134 6 33260 XOR
...
2 1 3542 3546 3535 AND
2 1 3535 3459 3462 XOR
2 1 3543 3541 3534 AND
...
1 1 3452 3449 INV
...
```

The first line

```
36663 36919
```

means that the entire circuit has 36663 gates and 36919 wires.

The second line

```
2 128 128
```

means that the circuit has 2 inputs, both inputs have 128 bits.

The third line

```
1 128
```

means that the circuit has 1 output, and the length is 128 bits.

The following lines are the gates in the circuit. For example

```
2 1 128 0 33254 XOR
```

means that this gate has a fan-in of 2 and fan-out of 1. The first input wire is
128 (the number of wires), the second input wire is 0, and the output wire
is 33254. The operation of this gate is $\xor$.

```
2 1 3542 3546 3535 AND
```

means that this gate has a fan-in of 2 and fan-out of 1. The first input wire is
3542, the second input wire is 3546, and the output wire is 3535. The operation
of this gate is $\and$.

```
1 1 3452 3449 INV
```

means that this gate has a fan-in of 1 and fan-out of 1. The input wire is 3452,
and the output wire is 3449. The operation of this gate is $\inv$.
