.section .text
.globl _start

_start:
    li t0, 100            # t0 = 100
    addi t1, t0, 2047     # t1 = t0 + 2047 (Expected: t1 = 2147)

    li t2, 1000           # t2 = 1000
    addi t3, t2, -2048    # t3 = t2 + (-2048) (Expected: t1 = -1048)

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
