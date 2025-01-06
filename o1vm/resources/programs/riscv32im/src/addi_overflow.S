.section .text
.globl _start

_start:
    li t0, 2147483647    # t0 = 2147483647 (Max 32-bit signed int)
    addi t1, t0, 1       # t1 = t0 + 1 (Expected: overflow to -2147483648)

    li t2, -2147483648   # t2 = -2147483648 (Min 32-bit signed int)
    addi t3, t2, -1      # t3 = t2 + (-1) (Expected: overflow to 2147483647)

    li t4, 123456789     # t4 = 123456789
    addi t5, t4, 0       # t5 = t4 + 0 (Expected: t4 = 123456789)

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
