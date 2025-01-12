.section .text
.globl _start

_start:
    li t0, 5             # t0 = 5
    li t1, 10            # t1 = 10

    # Swap t0 and t1 using add
    add t2, t0, t1       # t2 = t0 + t1 (t2 = 5 + 10 = 15)
    sub t0, t2, t0       # t0 = t2 - t0 (t0 = 15 - 5 = 10)
    sub t1, t2, t1       # t1 = t2 - t1 (t1 = 15 - 10 = 5)

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
