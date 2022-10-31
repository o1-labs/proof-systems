//~ The Keccak gadget is comprised of 3 circuit gates (Xor16, Rot64, and Zero)
//~
//~ Keccak works with 64-bit words. The state is represented using $5\times 5$ matrix
//~ of 64 bit words. Each compression step of Keccak consists of 24 rounds. Let us
//~ denote the state matrix with A (indexing elements as A[x,y]), from which we derive
//~further states as follows in each round. Each round then consists of the following 5 steps:
//~
//~ $$
//~ \begin{align}
//~ C[x] &= A[x,0] \oplus A[x,1] \oplus A[x,2] \oplus A[x,3] \oplus A[x,4] \\
//~ D[x] &= C[x-1] \oplus ROT(C[x+1],1) \\
//~ E[x,y] &= A[x,y]  \oplus D[x] \\
//~ B[y,2x+3y] &= ROT(E[x,y],\rho[x,y]) \\
//~ F[x,y] &= B[x,y] \oplus ((NOT B[x+1,y]) AND B[x+2,y]) \\
//~ Fp[0,0] &= F[0,0] \oplus RC
//~ \end{align}
//~ $$
//~
//~ FOR $0\leq x, y \leq 4$ and $\rho[x,y]$ is the rotation offset defined for Keccak.
//~ The values are in the table below extracted from the Keccak reference
//~ <https://keccak.team/files/Keccak-reference-3.0.pdf>
//~
//~ |       | x = 3 | x = 4 | x = 0 | x = 1 | x = 2 |
//~ | ----- | ----- | ----- | ----- | ----- | ----- |
//~ | y = 2 |  155  |  231  |    3  |   10  |  171  |
//~ | y = 1 |   55  |  276  |   36  |  300  |    6  |
//~ | y = 0 |   28  |   91  |    0  |    1  |  190  |
//~ | y = 4 |  120  |   78  |  210  |   66  |  253  |
//~ | y = 3 |   21  |  136  |  105  |   45  |   15  |
//~
//~ ##### Design Approach:
//~
//~ The atomic operations are XOR, ROT, NOT, AND. In the sections below, we will describe
//~ the gates for these operations. Below are some common approaches followed in their design.
//~
//~ To fit within 15 wires, we first decompose each word into its lower and upper 32-bit
//~ components. A gate for an atomic operation works with those 32-bit components at a time.
//~
//~ Before we describe the specific gate design approaches, below are some constraints in the
//~ Kimchi framework that dictated those approaches.
//~ * only 4 lookups per row
//~ * only first 7 columns are available to the permutation polynomial
//~
