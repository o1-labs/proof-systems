.section .text
.globl _start

_start:
    li t0, 100            # t0 = 100

    # Subtract 50 using addi (addi with negative immediate)
    addi t1, t0, -50      # t1 = t0 + (-50) (Expected: t1 = 50)

    # Subtract 100 using addi (addi with negative immediate)
    addi t2, t1, -100     # t2 = t1 + (-100) (Expected: t2 = -50)

    li t3, -1000          # t3 = -1000
    addi t4, t3, -500     # t4 = t0 + (-500) (Expected: t4 = -1500)

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
