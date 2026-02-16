.section .text
.globl _start

_start:

    # SLT with t0 < t1 (Expected: 1)
    li t0, 100            # t0 = 100
    li t1, 200            # t1 = 200
    slt t2, t0, t1        # t2 = (t0 < t1) ? 1 : 0 (Expected: t2 = 1)

    # SLT with t3 > t4 (Expected: 0)
    li t3, 300            # t3 = 300
    li t4, 200            # t4 = 200
    slt t5, t3, t4        # t5 = (t3 < t4) ? 1 : 0 (Expected: t5 = 0)

    # SLT with t0 == t1 (Expected: 0)
    li t0, 150            # t6 = 150
    li t1, 150            # t7 = 150
    slt t6, t0, t1        # t6 = (t0 < t1) ? 1 : 0 (Expected: t6 = 0)

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
