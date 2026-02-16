.section .text
.global _start

# t0 <- t0 + t1
add_t0_t1:
  add t0, t0, t1
  ret

_start:
  li t0, 5
  li t1, 7
  # Could be jalr
  # jal without offset
  jal ra, add_t0_t1

  # exit
  li a0, 0
  li a1, 0
  li a2, 0
  li a3, 0
  li a4, 0
  li a5, 0
  li a6, 0
  li a7, 42
  ecall
