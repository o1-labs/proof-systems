.section .text
.globl _start

_start:
    # Test 5: Result of subtracting from a register (using same value)
    li t0, 1234           # t0 = 1234
    sub t1, t0, t0        # t1 = t0 - t0 (Expected: t1 = 0)

    # Test 6: Handling overflow (large subtraction result)
    li t2, 2147483647     # t2 = 2147483647 (max positive signed 32-bit)
    li t3, -1             # t3 = -1
    sub t4, t2, t3        # t4 = t2 - t3 (Expected: t0 = 2147483648, wraparound to -2147483648)
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
