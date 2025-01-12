.section .text
.globl _start

_start:

    # Test 3: Subtracting a larger value (result negative)
    li t0, 300            # t0 = 300
    li t1, 500            # t1 = 500
    sub t2, t0, t1        # t2 = t0 - t1 (Expected: t2 = -200)

    # Test 4: Subtracting negative values (result positive)
    li t3, 100            # t3 = 100
    li t4, -50            # t4 = -50
    sub t5, t3, t4        # t5 = t3 - t4 (Expected: t5 = 150)

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
