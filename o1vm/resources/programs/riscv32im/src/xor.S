.section .text
.globl _start

_start:

    # Simple XOR
    li t0, 0b1100         # t0 = 0b1100
    li t1, 0b1010         # t1 = 0b1010
    xor t2, t0, t1        # t2 = t0 ^ t1 (Expected: t2 = 0b0110)

    # XOR with zero (no change)
    li t3, 0b1010         # t3 = 0b1010
    li t4, 0              # t4 = 0
    xor t5, t3, t4        # t5 = t3 ^ t4 (Expected: t5 = 0b1010)

    # XOR of identical values (result 0)
    li t6, 0b1111         # t6 = 0b1111
    li t0, 0b1111         # t0 = 0b1111
    xor t1, t6, t0        # t1 = t6 ^ t0 (Expected: t1 = 0)

    # Custom exit syscall
    li a0, 0
    li a1, 0
    li a2, 0
    li a3, 0
    li a4, 0
    li a5, 0
    li a6, 0
    li a7, 42
    ecall
