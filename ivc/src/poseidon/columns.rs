use kimchi_msm::columns::{Column, ColumnIndexer};
/// Column layout:
/// | W0 | W1 | W2 | W3 | W4 | W5 |||||| F0 | F1 | F2 | F3 | F4 | F5 |
/// |----|----|----|----|----|----||||||----|----|----|----|----|----|
/// | s0 | s1 | s2 | a0 | a1 | ck |||||| r0 | r1 | r2 | si | sa | sc |
///
/// with s0 to s2 being the initial state, and r0 to r2 the round constants
/// if selector sa is enabled a0 and a1 will be absorbed in the resulting state
/// the sa selector will make the result 0 so that we can start a new hash
/// and enabling the sc selector will assert that s0 == ck
/// An example hashing 4 elements x0,y0,x1,y1 may look like this:
///
/// -----------------------------------------------------------------------
///      | s0 | s1 | s2 | a0 | a1 | ck |||||| r0 | r1 | r2 | si | sa | sc |
///   0> | -  | -  | -  | x0 | y0 | -  |||||| cc | cc | cc | 1  | 1  | 0  |
///   1> | x0 | y0 | ~  | -  | -  | -  |||||| cc | cc | cc | 0  | 0  | 0  |
///   2> | ~  | ~  | ~  | -  | -  | -  |||||| cc | cc | cc | 0  | 0  | 0  |
/// last round here, we absorb up to 2 extra elements and continue
///  55> | ~  | ~  | ~  | x1 | y1 | -  |||||| cc | cc | cc | 0  | 1  | 0  |
/// first round after absorbing
///  56> | ~  | ~  | ~  | -  | -  | -  |||||| cc | cc | cc | 0  | 0  | 0  |
/// 109> | ~  | ~  | ~  | -  | -  | -  |||||| cc | cc | cc | 0  | 0  | 0  |
/// after absorbing last element assert the hash to be h
/// 110> | h  | ~  | ~  | -  | -  | h  |||||| cc | cc | cc | 0  | 0  | 1  |
/// we can also set init and absorb to start hashing a new set of elements
/// 110> | h  | ~  | ~  | x' | y' | h  |||||| cc | cc | cc | 1  | 1  | 1  |
/// at the end it can be padded like this
/// 111> | 0  | 0  | 0  | 0  | 0  | 0  |||||| cc | cc | cc | 1  | 1  | 0  |
/// 112> | 0  | 0  | 0  | 0  | 0  | 0  |||||| cc | cc | cc | 1  | 1  | 0  |
/// -----------------------------------------------------------------------
/// with ~ being intermediate results of hashing, and - being arbitrary values
/// which are inrelevant for constraints in that particular row due to the
/// selectors.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Power {
    // 0..=2
    Square(usize),
    // 0..=2
    Fourth(usize),
    // 0..=2
    Sixth(usize),
    // 0..=2
    Seventh(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Selector {
    /// This will make the constraints apply the round to a 0 state, ignoring
    /// the result of the previous round
    Init,
    /// This will add the 2 values present in the absorb columns to the result
    /// of applying the round, thus absorbing them
    Absorb,
    /// enables assertion of equality between the output hash and the content
    /// of the check column
    CheckEnabled,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PoseidonColumn {
    // 0..=2
    State(usize),
    // (0..=2)
    RoundConstant(usize),
    // 0..=1
    Absorb(usize),
    Check,
    // for the x^7 constraints
    Powers(Power),
    Mode(Selector),
}

impl ColumnIndexer for PoseidonColumn {
    // 3 for state
    // 3 for constants
    // 2 for absorb
    // 1 for check
    // 12 for powers
    // 3 for selector
    const N_COL: usize = 3 + 3 + 2 + 1 + 12 + 3;

    fn to_column(self) -> Column {
        use PoseidonColumn::*;
        match &self {
            State(i)
            | RoundConstant(i)
            | Absorb(i)
            | Powers(Power::Square(i))
            | Powers(Power::Fourth(i))
            | Powers(Power::Sixth(i))
            | Powers(Power::Seventh(i)) => {
                assert!(i < &3);
            }
            _ => {}
        };
        let i = match self {
            State(i) => i + 3 * 0,
            Absorb(i) => i + 3 * 1,
            Check => 6,
            Powers(Power::Square(i)) => i + 3 * 2 + 1,
            Powers(Power::Fourth(i)) => i + 3 * 3 + 1,
            Powers(Power::Sixth(i)) => i + 3 * 4 + 1,
            Powers(Power::Seventh(i)) => i + 3 * 5 + 1,
            RoundConstant(i) => return Column::FixedSelector(i),
            Mode(s) => match s {
                Selector::Init => return Column::FixedSelector(3 + 0),
                Selector::Absorb => return Column::FixedSelector(3 + 1),
                Selector::CheckEnabled => return Column::FixedSelector(3 + 2),
            },
        };
        Column::Relation(i)
    }
}
