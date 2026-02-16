.section .text
.globl _start

_start:

    # Test 1: Simple subtraction
    li t0, 1000           # t0 = 1000
    li t1, 500            # t1 = 500
    sub t2, t0, t1        # t2 = t0 - t1 (Expected: t2 = 500)

    # Test 2: Subtracting from zero
    li t3, 0              # t3 = 0
    li t4, 100            # t4 = 100
    sub t5, t3, t4        # t5 = t3 - t4 (Expected: t5 = -100)

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
