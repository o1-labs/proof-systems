.section .text
.global _start

exit_success:
  li a0, 0
  li a1, 0
  li a2, 0
  li a3, 0
  li a4, 0
  li a5, 0
  li a6, 0
  li a7, 42
  ecall

# Reduce a0 into the field. It does suppose that a0
# is a 32-bit number.
# We only deal with positive values.
# The input is located in a0, and the output
# is located also in a0.
# FIXME: calling convention should be respected here...
# That's ugly.
# Use temprary registers like t0-t6, and copy into the stack.
reduce_in_field:
  li t0, 0x7fffffff
  remu a0, a0, t0
  ret

mersenne_add:
  add sp, sp, -4
  sw ra, 0(sp)

  add a0, a0, a1
  jal ra, reduce_in_field

  lw ra, 0(sp)
  add sp, sp, 4
  ret

_start:
  # Loading arguments
  li a0, 0
  li a1, 0x04

  jal ra, mersenne_add

  # Result is located in a0.
  # Saving on the stack
  sw a0, 0(sp)

  jal ra, exit_success
