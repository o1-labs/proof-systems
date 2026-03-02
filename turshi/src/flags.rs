//! Definition of some constants for easier readability of the steps.
//! When they refer to single bit flagsets, only one constant is needed.

/// Number of Cairo flags
pub const NUM_FLAGS: usize = 16;
/// Position of destination offset of 16 bits within instruction decomposition
pub const POS_DST: usize = 0;
/// Position of first operand offset of 16 bits within instruction decomposition
pub const POS_OP0: usize = 1;
/// Position of second operand offset of 16 bits within instruction decomposition
pub const POS_OP1: usize = 2;
/// Bit position of the beginning of the flags in a Cairo instruction
pub const POS_FLAGS: usize = 48;

/// Destination refers to ap register
pub const DST_AP: u8 = 0;

/// First operand refers to ap register
pub const OP0_AP: u8 = 0;

/// Second operand is double indexing
pub const OP1_DBL: u8 = 0;
/// Second operand is immediate value
pub const OP1_VAL: u8 = 1;
/// Second operand refers to fp register
pub const OP1_FP: u8 = 2;
/// Second operand refers to ap register
pub const OP1_AP: u8 = 4;

/// Result is a single operand
pub const RES_ONE: u8 = 0;
/// Result is an addition
pub const RES_ADD: u8 = 1;
/// Result is a multiplication
pub const RES_MUL: u8 = 2;

/// Default increase of pc by adding instruction size
pub const PC_SIZ: u8 = 0;
/// Update pc by an absolute jump
pub const PC_ABS: u8 = 1;
/// Update pc by a relative jump
pub const PC_REL: u8 = 2;
/// Update pc by a conditional relative jump
pub const PC_JNZ: u8 = 4;

/// Update by 2 in call instructions or zero behaviour for other instructions
pub const AP_Z2: u8 = 0;
/// Update ap by adding a number of positions
pub const AP_ADD: u8 = 1;
/// Update ap by self increment
pub const AP_ONE: u8 = 2;

/// Operation code is a jump or an increment
pub const OPC_JMP_INC: u8 = 0;
/// Operation code is a call
pub const OPC_CALL: u8 = 1;
/// Operation code is a return
pub const OPC_RET: u8 = 2;
/// Operation code is an assert-equal
pub const OPC_AEQ: u8 = 4;
