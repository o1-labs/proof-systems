###############################################################################
# File         : jr.asm
# Project      : MIPS32 MUX
# Author:      : Grant Ayers (ayers@cs.stanford.edu)
#
# Standards/Formatting:
#   MIPS gas, soft tab, 80 column
#
# Description:
#   Test the functionality of the 'jr' instruction.
#
###############################################################################


.section .text
.global __start
__start:
    lui     $s0, 0xbfff         # Load the base address 0xbffffff0
    ori     $s0, 0xfff0
    ori     $s1, $0, 1          # Prepare the 'done' status

    #### Test code start ####

    la      $t0, $target
    jr      $t0
    ori     $v0, $0, 0          # The test result starts as a failure

$finish:
    sw      $v0, 8($s0)
    sw      $s1, 4($s0)
    jr      $ra
    nop
    j       $finish             # Early-by-1 detection

$target:
    nop
    ori     $v0, $0, 1          # Set the result to pass
    j       $finish
    nop

    #### Test code end ####

