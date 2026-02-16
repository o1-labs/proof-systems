.section .text
.globl _start

_start:
    # Initialize registers
    li t0, 0          # t0 will hold the running total (initialize to 0)
    li t1, 1          # First number
    li t2, 2          # Second number
    li t3, 3          # Third number
    li t4, 4          # Fourth number
    li t5, 5          # Fifth number

    # Perform additions
    add t0, t0, t1    # t0 = t0 + t1 (0 + 1)
    add t0, t0, t2    # t0 = t0 + t2 (1 + 2)
    add t0, t0, t3    # t0 = t0 + t3 (3 + 3)
    add t0, t0, t4    # t0 = t0 + t4 (6 + 4)
    add t0, t0, t5    # t0 = t0 + t5 (10 + 5)

    # Custom exit syscall
    li a0, 0          # Set a0 to 0
    li a1, 0          # Set a1 to 0
    li a2, 0          # Set a2 to 0
    li a3, 0          # Set a3 to 0
    li a4, 0          # Set a4 to 0
    li a5, 0          # Set a5 to 0
    li a6, 0          # Set a6 to 0
    li a7, 42         # Set a7 to 42 (custom ecall number)
    ecall             # Trigger syscall
