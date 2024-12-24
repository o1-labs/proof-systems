.section .text
.global __start

__start:
  # fnctl(0, 3)
  li $v0, 4055
  li $a0, 0x0
  li $a1, 0x3
  syscall
  sltiu $v0, $v0, 1

# save results
  lui     $s0, 0xbfff         # Load the base address 0xbffffff0
  ori     $s0, 0xfff0
  ori     $s1, $0, 1          # Prepare the 'done' status

  sw      $v0, 8($s0)         # Set the test result
  sw      $s1, 4($s0)         # Set 'done'

$done:
  jr $ra
  nop

