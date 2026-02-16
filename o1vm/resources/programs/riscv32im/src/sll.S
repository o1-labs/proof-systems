.global _start

_start:
  # Load 2^12 in the register t0
  lui t0, 0b1
  # Multiply by 4
  sll t0, t0, 2
  li a0, 0
  li a1, 0
  li a2, 0
  li a3, 0
  li a4, 0
  li a5, 0
  li a6, 0
  li a7, 42
  ecall
