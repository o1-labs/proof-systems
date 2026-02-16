.section .text
.globl _start

_start:
    # Unsigned remainder by zero (remu)
    li t0, 42             # t0 = 42
    li t1, 0              # t1 = 0
    remu t2, t0, t1       # t2 = t0 % t1 (Expected: remainder by zero)

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
