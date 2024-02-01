use ark_ff::Field;

#[derive(Copy, Clone, Debug)]
pub enum LookupTable {
    RangeCheck16 = 1,
}

pub struct Lookup<F: Field> {
    pub(crate) table_id: LookupTable,
    pub(crate) numerator: F,
    pub(crate) value: Vec<F>,
}
