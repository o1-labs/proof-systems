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

_start:
  lui t0, 0x42
  sll t0, t0, 2
  jal exit_success
