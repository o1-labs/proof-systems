.section .text
.globl _start

_start:
  # Initialize register
  li t0, 10         # Load immediate value 10 into t0

  # Perform addition
  addi t0, t0, 5    # Add 5 to the value in t0 and store the result back in t0

  # Custom exit syscall
  li a0, 0          # Set a0 to 0
  li a1, 0          # Set a1 to 0
  li a2, 0          # Set a2 to 0
  li a3, 0          # Set a3 to 0
  li a4, 0          # Set a4 to 0
  li a5, 0          # Set a5 to 0
  li a6, 0          # Set a6 to 0
  li a7, 42         # Set a7 to 42 (custom ecall number)
  ecall
