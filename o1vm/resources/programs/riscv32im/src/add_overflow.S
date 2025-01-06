# The addition performed by `add` is simply a bit-wise addition
# The lowest 32 bits are kept, and no overflow bit is kept.
.section .text
.globl _start

_start:
    # Large positive values
    # It is equal to
    # 0b01111111111111111111111111111111 +
    # 0b00000000000000000000000000000001 =
    # 0b10000000000000000000000000000000 =
    li t0, 2147483647    # t0 = 2147483647 (Max 32-bit signed int)
    li t1, 1             # t1 = 1
    add t2, t0, t1       # t2 = t0 + t1

    # 0b11111111111111111111111111111111 +
    # 0b00000000000000000000000000000001 =
    # 0b00000000000000000000000000000000 =
    li t3, 0b11111111111111111111111111111111
    add t4, t3, t1       # t4 = t3 + t1 (Expected: overflow, wrap around)

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
