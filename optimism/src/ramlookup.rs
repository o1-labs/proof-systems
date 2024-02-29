use ark_ff::{Field, One, Zero};
use kimchi_msm::MVLookupTableID;

#[derive(Copy, Clone, Debug)]
pub enum LookupMode {
    Read,
    Write,
}

#[derive(Clone, Debug)]
pub struct Lookup<T, ID: MVLookupTableID + Send + Sync + Copy> {
    pub mode: LookupMode,
    /// The number of times that this lookup value should be added to / subtracted from the lookup accumulator.
    pub magnitude: T,
    pub table_id: ID,
    pub value: Vec<T>,
}

impl<T, ID: MVLookupTableID + Send + Sync + Copy> Lookup<T, ID>
where
    T: Clone
        + std::ops::Add<T, Output = T>
        + std::ops::Sub<T, Output = T>
        + std::ops::Mul<T, Output = T>
        + std::fmt::Debug
        + One
        + Zero,
{
    fn numerator(&self) -> T {
        match self.mode {
            LookupMode::Read => T::zero() - self.magnitude.clone(),
            LookupMode::Write => self.magnitude.clone(),
        }
    }
    /// Reads one value when `if_is_true` is 1.
    pub fn read_if(if_is_true: T, table_id: ID, value: Vec<T>) -> Self {
        Self {
            mode: LookupMode::Read,
            magnitude: if_is_true,
            table_id,
            value,
        }
    }

    /// Writes one value when `if_is_true` is 1.
    pub fn write_if(if_is_true: T, table_id: ID, value: Vec<T>) -> Self {
        Self {
            mode: LookupMode::Write,
            magnitude: if_is_true,
            table_id,
            value,
        }
    }

    /// Reads one value from a table.
    pub fn read_one(table_id: ID, value: Vec<T>) -> Self {
        Self {
            mode: LookupMode::Read,
            magnitude: T::one(),
            table_id,
            value,
        }
    }

    /// Writes one value to a table.
    pub fn write_one(table_id: ID, value: Vec<T>) -> Self {
        Self {
            mode: LookupMode::Write,
            magnitude: T::one(),
            table_id,
            value,
        }
    }
}

impl<F: std::fmt::Display + Field, ID: MVLookupTableID + Send + Sync + Copy> std::fmt::Display
    for Lookup<F, ID>
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let numerator = match self.mode {
            LookupMode::Read => -self.magnitude,
            LookupMode::Write => self.magnitude,
        };
        write!(
            formatter,
            "numerator: {}\ntable_id: {:?}\nvalue:\n[\n",
            numerator,
            self.table_id.into_field::<F>()
        )?;
        for value in self.value.iter() {
            writeln!(formatter, "\t{}", value)?;
        }
        write!(formatter, "]")?;
        Ok(())
    }
}

/// A table of values that can be used for a lookup, along with the ID for the table.
#[derive(Debug, Clone)]
pub struct LookupTable<F, ID: MVLookupTableID + Send + Sync + Copy> {
    /// Table ID corresponding to this table
    #[allow(dead_code)]
    pub table_id: ID,
    /// Vector of values inside each entry of the table
    #[allow(dead_code)]
    pub entries: Vec<Vec<F>>,
}
