/// Layout variable handling
///
///   First, you use "anchor" names for the variables when specifying
///   the witness layout.
///
///   Ex.
///```ignore
///     let layout = [
///         [
///             &CopyShiftCell::create(0, 2, 8),
///             &VariableCell::create("sum_of_products"),
///             ...
///             &VariableCell::create("final_value"),
///         ]
///      ;
///```
///
///   Second, you use variables with the same names when performing the
///   witness computation.
///
///   Ex.
///```ignore
///
///     let sum_of_products = carry1 * limb1 + pow1 * limb2;
///     ...
///     let final_value = middle_bits.pow(&[2u8]) * carry_flag
///```
///
///   Third, when you're ready to generate the witness, you pass those
///   variables to the witness creation functions using variables!(foo, bar)
///   or variable_map!("foo" => 12, "bar" => blah).
///```ignore
///     Ex.
///
///     init_witness(
///         &mut witness2,
///         &layout,
///         &variables!(sum_of_products, something_else, final_value),
///     );
///```
///
use std::{
    collections::HashMap,
    ops::{Index, IndexMut},
};

/// Layout variables mapping - these values are substituted
/// into the witness layout when creating the witness instance.
///
///   Map of witness values (used by VariableCells)
///     name (String) -> value (F)
pub struct Variables<'a, T>(HashMap<&'a str, T>);

impl<'a, T> Variables<'a, T> {
    /// Create a layout variable map
    pub fn create() -> Variables<'a, T> {
        Variables(HashMap::new())
    }

    /// Insert a variable and corresponding value into the variable map
    pub fn insert(&mut self, name: &'a str, value: T) {
        self.0.insert(name, value);
    }
}

impl<'a, T> Index<&'a str> for Variables<'a, T> {
    type Output = T;
    fn index(&self, name: &'a str) -> &Self::Output {
        &self.0[name]
    }
}

impl<'a, T> IndexMut<&'a str> for Variables<'a, T> {
    fn index_mut(&mut self, name: &'a str) -> &mut Self::Output {
        self.0.get_mut(name).expect("failed to get witness value")
    }
}

/// Macro to simplify mapping of layout variable
#[macro_export]
macro_rules! variables {
    () => {
        Variables::create()
    };
    ($( $var: ident ),*) => {{
         let mut vars = Variables::create();
         $( vars.insert(stringify!{$var}, $var); )*
         vars
    }}
}

/// Macro to simplify creation of layout map
#[macro_export]
macro_rules! variable_map {
    [$( $name: expr => $value: expr ),*] => {{
        let mut vars = Variables::create();
        $( vars.insert($name, $value); )*
        vars
    }}
}

pub use variable_map;
pub use variables;
