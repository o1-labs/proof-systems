/// Defining some constants for easier readability of the steps
/// When they refer to single bit flagsets, only one constant is needed

/// Destination refers to ap register
pub const DST_AP: u64 = 0;

/// First operand refers to ap register
pub const OP0_AP: u64 = 0;

/// Second operand is double indexing
pub const OP1_DBL: u64 = 0;
/// Second operand is immediate value
pub const OP1_VAL: u64 = 1;
/// Second operand refers to fp register
pub const OP1_FP: u64 = 2;
/// Second operand refers to ap register
pub const OP1_AP: u64 = 4;

/// Result is a single operand
pub const RES_ONE: u64 = 0;
/// Result is an addition
pub const RES_ADD: u64 = 1;
/// Result is a multiplication
pub const RES_MUL: u64 = 2;

/// Default increase of pc by adding instruction size
pub const PC_SIZ: u64 = 0;
/// Update pc by an absolute jump
pub const PC_ABS: u64 = 1;
/// Update pc by a relative jump
pub const PC_REL: u64 = 2;
/// Update pc by a conditional relative jump
pub const PC_JNZ: u64 = 4;

/// Update by 2 in call instructions or zero behaviour for other instructions
pub const AP_Z2: u64 = 0;
/// Update ap by adding a number of positions
pub const AP_ADD: u64 = 1;
/// Update ap by self increment
pub const AP_ONE: u64 = 2;

/// Operation code is a jump or an increment
pub const OPC_JMP_INC: u64 = 0;
/// Operation code is a call
pub const OPC_CALL: u64 = 1;
/// Operation code is a return
pub const OPC_RET: u64 = 2;
/// Operation code is an assert-equal
pub const OPC_AEQ: u64 = 4;
