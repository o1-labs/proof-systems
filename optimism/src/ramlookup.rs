use ark_ff::{Field, One, Zero};
use kimchi_msm::{MVLookup, MVLookupTableID};

/// Enum representing the two different modes of a RAMLookup
#[derive(Copy, Clone, Debug)]
pub enum LookupMode {
    Read,
    Write,
}

/// Struct containing a RAMLookup
#[derive(Clone, Debug)]
pub struct Lookup<T, ID: MVLookupTableID + Send + Sync + Copy> {
    /// The table ID corresponding to this lookup
    pub(crate) table_id: ID,
    /// Whether it is a read or write lookup
    pub(crate) mode: LookupMode,
    /// The number of times that this lookup value should be added to / subtracted from the lookup accumulator.
    pub(crate) magnitude: T,
    /// The columns containing the content of this lookup
    pub(crate) value: Vec<T>,
}

impl<T, ID> Lookup<T, ID>
where
    T: Clone
        + std::ops::Add<T, Output = T>
        + std::ops::Sub<T, Output = T>
        + std::ops::Mul<T, Output = T>
        + std::fmt::Debug
        + One
        + Zero,
    ID: MVLookupTableID + Send + Sync + Copy,
{
    /// Creates a new RAMLookup from a mode, a table ID, a magnitude, and a value
    pub fn new(mode: LookupMode, table_id: ID, magnitude: T, value: &[T]) -> Self {
        Self {
            mode,
            table_id,
            magnitude,
            value: value.to_vec(),
        }
    }

    /// Returns the numerator corresponding to this lookup in the MVLookup argument
    pub fn numerator(&self) -> T {
        match self.mode {
            LookupMode::Read => T::zero() - self.magnitude.clone(),
            LookupMode::Write => self.magnitude.clone(),
        }
    }

    /// Transforms the current RAMLookup into an equivalent MVLookup
    pub fn into_mvlookup(self) -> MVLookup<T, ID> {
        MVLookup::new(self.table_id, self.numerator(), &self.value)
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
