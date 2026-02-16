.section .text
.globl _start

_start:
    li t0, 10000000         # Large number
    li t1, 10000000         # Another large number
    mul t2, t0, t1          # Test large multiplication (Expected overflow)

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
