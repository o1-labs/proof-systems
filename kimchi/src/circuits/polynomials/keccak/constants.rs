/// Constants for each witness' index offsets and lengths
// KECCAK PARAMETERS
/// The dimension of the Keccak state
pub const DIM: usize = 5;

/// An element of the Keccak state is 64 bits. However, we split the state into
/// quarters of 16 bits to represent XOR and AND using the finite field
/// addition. See the Keccak RFC for more information.
pub const QUARTERS: usize = 4;

pub const SHIFTS: usize = 4;

/// The number of rounds in the Keccak permutation
pub const ROUNDS: usize = 24;

/// The number of bytes that can be processed by the Keccak permutation. It is
/// the rate of the sponge configuration.
pub const RATE_IN_BYTES: usize = 1088 / 8;

/// The number of bytes used as a capacity in the sponge.
pub const CAPACITY_IN_BYTES: usize = 512 / 8;

/// The number of columns the Keccak circuit uses.
pub const KECCAK_COLS: usize = 1965;

/// The number of field elements used to represent the whole Keccak state.
pub const STATE_LEN: usize = QUARTERS * DIM * DIM;

pub const SHIFTS_LEN: usize = SHIFTS * STATE_LEN;

// ROUND INDICES

pub const THETA_STATE_A_OFF: usize = 0;
pub const THETA_STATE_A_LEN: usize = STATE_LEN;
pub const THETA_SHIFTS_C_OFF: usize = THETA_STATE_A_LEN;
pub const THETA_SHIFTS_C_LEN: usize = SHIFTS * DIM * QUARTERS;
pub const THETA_DENSE_C_OFF: usize = THETA_SHIFTS_C_OFF + THETA_SHIFTS_C_LEN;
pub const THETA_DENSE_C_LEN: usize = QUARTERS * DIM;
pub const THETA_QUOTIENT_C_OFF: usize = THETA_DENSE_C_OFF + THETA_DENSE_C_LEN;
pub const THETA_QUOTIENT_C_LEN: usize = DIM;
pub const THETA_REMAINDER_C_OFF: usize = THETA_QUOTIENT_C_OFF + THETA_QUOTIENT_C_LEN;
pub const THETA_REMAINDER_C_LEN: usize = QUARTERS * DIM;
pub const THETA_DENSE_ROT_C_OFF: usize = THETA_REMAINDER_C_OFF + THETA_REMAINDER_C_LEN;
pub const THETA_DENSE_ROT_C_LEN: usize = QUARTERS * DIM;
pub const THETA_EXPAND_ROT_C_OFF: usize = THETA_DENSE_ROT_C_OFF + THETA_DENSE_ROT_C_LEN;
pub const THETA_EXPAND_ROT_C_LEN: usize = QUARTERS * DIM;
pub const PIRHO_SHIFTS_E_OFF: usize = THETA_EXPAND_ROT_C_OFF + THETA_EXPAND_ROT_C_LEN;
pub const PIRHO_SHIFTS_E_LEN: usize = SHIFTS_LEN;
pub const PIRHO_DENSE_E_OFF: usize = PIRHO_SHIFTS_E_OFF + PIRHO_SHIFTS_E_LEN;
pub const PIRHO_DENSE_E_LEN: usize = STATE_LEN;
pub const PIRHO_QUOTIENT_E_OFF: usize = PIRHO_DENSE_E_OFF + PIRHO_DENSE_E_LEN;
pub const PIRHO_QUOTIENT_E_LEN: usize = STATE_LEN;
pub const PIRHO_REMAINDER_E_OFF: usize = PIRHO_QUOTIENT_E_OFF + PIRHO_QUOTIENT_E_LEN;
pub const PIRHO_REMAINDER_E_LEN: usize = STATE_LEN;
pub const PIRHO_DENSE_ROT_E_OFF: usize = PIRHO_REMAINDER_E_OFF + PIRHO_REMAINDER_E_LEN;
pub const PIRHO_DENSE_ROT_E_LEN: usize = STATE_LEN;
pub const PIRHO_EXPAND_ROT_E_OFF: usize = PIRHO_DENSE_ROT_E_OFF + PIRHO_DENSE_ROT_E_LEN;
pub const PIRHO_EXPAND_ROT_E_LEN: usize = STATE_LEN;
pub const CHI_SHIFTS_B_OFF: usize = PIRHO_EXPAND_ROT_E_OFF + PIRHO_EXPAND_ROT_E_LEN;
pub const CHI_SHIFTS_B_LEN: usize = SHIFTS_LEN;
pub const CHI_SHIFTS_SUM_OFF: usize = CHI_SHIFTS_B_OFF + CHI_SHIFTS_B_LEN;
pub const CHI_SHIFTS_SUM_LEN: usize = SHIFTS_LEN;
pub const IOTA_STATE_G_OFF: usize = 0;
pub const IOTA_STATE_G_LEN: usize = STATE_LEN;
// SPONGE INDICES
pub const SPONGE_OLD_STATE_OFF: usize = 0;
pub const SPONGE_OLD_STATE_LEN: usize = STATE_LEN;
pub const SPONGE_NEW_STATE_OFF: usize = SPONGE_OLD_STATE_OFF + SPONGE_OLD_STATE_LEN;
pub const SPONGE_NEW_STATE_LEN: usize = STATE_LEN;
pub const SPONGE_NEW_BLOCK_OFF: usize = SPONGE_NEW_STATE_OFF;
pub const SPONGE_NEW_BLOCK_LEN: usize = 68;
pub const SPONGE_ZEROS_OFF: usize = SPONGE_NEW_BLOCK_OFF + SPONGE_NEW_BLOCK_LEN;
pub const SPONGE_ZEROS_LEN: usize = STATE_LEN - SPONGE_NEW_BLOCK_LEN;
pub const SPONGE_BYTES_OFF: usize = SPONGE_NEW_STATE_OFF + SPONGE_NEW_STATE_LEN;
pub const SPONGE_BYTES_LEN: usize = 2 * STATE_LEN;
pub const SPONGE_SHIFTS_OFF: usize = SPONGE_BYTES_OFF + SPONGE_BYTES_LEN;
pub const SPONGE_SHIFTS_LEN: usize = SHIFTS_LEN;
pub const SPONGE_XOR_STATE_OFF: usize = 0;
pub const SPONGE_XOR_STATE_LEN: usize = STATE_LEN;

/// The number of columns the Sponge circuit uses.
pub const SPONGE_COLS: usize = SPONGE_SHIFTS_OFF + SPONGE_SHIFTS_LEN;
