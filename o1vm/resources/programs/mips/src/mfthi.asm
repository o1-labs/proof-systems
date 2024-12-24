###############################################################################
# File         : mfthi.asm
# Project      : MIPS32 MUX
# Author:      : Grant Ayers (ayers@cs.stanford.edu)
#
# Standards/Formatting:
#   MIPS gas, soft tab, 80 column
#
# Description:
#   Test the functionality of the 'mthi' and 'mfhi' instructions.
#
###############################################################################


.section .text
.global __start
__start:
    lui     $s0, 0xbfff         # Load the base address 0xbffffff0
    ori     $s0, 0xfff0
    ori     $s1, $0, 1          # Prepare the 'done' status

    #### Test code start ####

    lui     $t0, 0xdeaf
    ori     $t0, 0xbeef
    mthi    $t0
    mfhi    $t1
    subu    $v1, $t0, $t1
    sltiu   $v0, $v1, 1

    #### Test code end ####

    sw      $v0, 8($s0)         # Set the test result
    sw      $s1, 4($s0)         # Set 'done'

$done:
    jr      $ra
    nop

