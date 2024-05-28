//! This module provides different helpers in creating constant sized
//! arrays and converting them to different formats.
//!
//! Functions in this module are not necessarily optimal in terms of
//! allocations, as they tend to create intermediate vectors. For
//! better performance, either optimise this code, or use
//! (non-fixed-sized) vectors.

// Use a generic function so that the pointer cast remains type-safe
/// Converts a vector of elements to a boxed one. Semantically
/// equivalent to `vector.into_boxed_slice().try_into().unwrap()`.
pub fn vec_to_boxed_array<T, const N: usize>(vec: Vec<T>) -> Box<[T; N]> {
    vec.into_boxed_slice().try_into().unwrap_or_else(|_| {
        panic!("vec_to_boxed_array: length mismatch, expected {}", N)
    })
}

// @volhovm It could potentially be more efficient with unsafe tricks.
/// Converts a two-dimensional vector to a constant sized two-dimensional array.
pub fn vec_to_boxed_array2<T, const N: usize, const M: usize>(
    vec: Vec<Vec<T>>,
) -> Box<[[T; N]; M]> {
    let vec_of_slices2: Vec<[T; N]> = vec
        .into_iter()
        .map(|x: Vec<T>| {
            let y: Box<[T]> = x.into_boxed_slice();
            let z: Box<[T; N]> = y
                .try_into()
                .unwrap_or_else(|_| panic!("vec_to_boxed_array2: length mismatch inner array"));
            *z
        })
        .collect();
    let array: Box<[[T; N]; M]> = vec_of_slices2
        .into_boxed_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("vec_to_boxed_array2: length mismatch outer array"));

    array
}

/// Converts a three-dimensional vector to a constant sized two-dimensional array.
pub fn vec_to_boxed_array3<T, const N: usize, const M: usize, const K: usize>(
    vec: Vec<Vec<Vec<T>>>,
) -> Box<[[[T; N]; M]; K]> {
    let vec_of_slices2: Vec<[[T; N]; M]> =
        vec.into_iter().map(|v| *vec_to_boxed_array2(v)).collect();
    vec_of_slices2
        .into_boxed_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("vec_to_boxed_array3: length mismatch outer array"))
}

/// A macro similar to `vec![$elem; $size]` which returns a boxed
/// array, allocated directly on the heap (via a vector, with reallocations).
///
/// ```rustc
///     let _: Box<[u8; 1024]> = box_array![0; 1024];
/// ```
///
/// See
/// <https://stackoverflow.com/questions/25805174/creating-a-fixed-size-array-on-heap-in-rust/68122278#68122278>
#[macro_export]
macro_rules! box_array {
    ($val:expr ; $len:expr) => {{
        // Use a generic function so that the pointer cast remains type-safe
        fn vec_to_boxed_array<T>(vec: Vec<T>) -> Box<[T; $len]> {
            (vec.into_boxed_slice())
                .try_into()
                .unwrap_or_else(|_| panic!("box_array: length mismatch"))
        }

        vec_to_boxed_array(vec![$val; $len])
    }};
}

/// A macro similar to `vec![vec![$elem; $size1]; $size2]` which
/// returns a two-dimensional boxed array, allocated directly on the
/// heap (via a vector, with reallocations).
///
/// ```rustc
///     let _: Box<[[u8; 1024]; 512]> = box_array![0; 1024; 512];
/// ```
///
#[macro_export]
macro_rules! box_array2 {
    ($val:expr; $len1:expr; $len2:expr) => {{
        pub fn vec_to_boxed_array2<T>(vec: Vec<Vec<T>>) -> Box<[[T; $len1]; $len2]> {
            let vec_of_slices2: Vec<[T; $len1]> = vec
                .into_iter()
                .map(|x: Vec<T>| {
                    let y: Box<[T]> = x.into_boxed_slice();
                    let z: Box<[T; $len1]> = y
                        .try_into()
                        .unwrap_or_else(|_| panic!("box_array2: length mismatch inner array"));
                    *z
                })
                .collect();
            let array: Box<[[T; $len1]; $len2]> = vec_of_slices2
                .into_boxed_slice()
                .try_into()
                .unwrap_or_else(|_| panic!("box_array2: length mismatch outer array"));

            array
        }

        vec_to_boxed_array2(vec![vec![$val; $len1]; $len2])
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_ec::AffineCurve;
    use ark_ff::Zero;
    use mina_curves::pasta::Pallas as CurvePoint;

    pub type BaseField = <CurvePoint as AffineCurve>::BaseField;

    #[test]
    /// Tests whether initialising different arrays creates a stack
    /// overflow. The usual default size of the stack is 128kB.
    fn test_boxed_stack_overflow() {
        // Each point is assumed to be 256 bits, so 512 points is
        // 16MB. This often overflows the stack if created as an
        // array.
        let _boxed: Box<[[BaseField; 256]; 1]> =
            vec_to_boxed_array2(vec![vec![BaseField::zero(); 256]; 1]);
        let _boxed: Box<[[BaseField; 64]; 4]> =
            vec_to_boxed_array2(vec![vec![BaseField::zero(); 64]; 4]);
        let _boxed: Box<[BaseField; 256]> = box_array![BaseField::zero(); 256];
        let _boxed: Box<[[BaseField; 256]; 1]> = box_array2![BaseField::zero(); 256; 1];
    }
}
