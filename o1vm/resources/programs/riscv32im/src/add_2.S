.section .text
.globl _start

_start:
    # Initialize registers with some numbers
    li t0, 123       # First number
    li t1, 456       # Second number
    li t2, 789       # Third number

    # Perform first addition
    add t3, t0, t1   # t3 = t0 + t1 (123 + 456 = 579)

    # Perform second addition
    add t4, t3, t2   # t4 = t3 + t2 (579 + 789 = 1368)

    # Add all numbers in a more complex way for redundancy
    add t5, t0, t2   # t5 = t0 + t2 (123 + 789 = 912)
    add t6, t1, t5   # t6 = t1 + t5 (456 + 912 = 1368)

    # Ensure final result matches expectations
    add t6, t4, x0   # t6 = t4 + x0 (Copy t4 to t6 for validation)

    # Custom exit syscall
    li a0, 0         # Set a0 to 0
    li a1, 0         # Set a1 to 0
    li a2, 0         # Set a2 to 0
    li a3, 0         # Set a3 to 0
    li a4, 0         # Set a4 to 0
    li a5, 0         # Set a5 to 0
    li a6, 0         # Set a6 to 0
    li a7, 42        # Set a7 to 42 (custom ecall number)
    ecall            # Trigger syscall
