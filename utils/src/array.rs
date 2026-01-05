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
    vec.into_boxed_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("vec_to_boxed_array: length mismatch, expected {}", N))
}

// @volhovm It could potentially be more efficient with unsafe tricks.
/// Converts a two-dimensional vector to a constant sized two-dimensional array.
pub fn vec_to_boxed_array2<T: Clone, const N: usize, const M: usize>(
    vec: Vec<Vec<T>>,
) -> Box<[[T; N]; M]> {
    let mut vec_of_slices2: Vec<[T; N]> = vec![];
    vec.into_iter().for_each(|x: Vec<T>| {
        let y: Box<[T]> = x.into_boxed_slice();
        let z: Box<[T; N]> = y
            .try_into()
            .unwrap_or_else(|_| panic!("vec_to_boxed_array2: length mismatch inner array"));
        let zz: &[[T; N]] = std::slice::from_ref(z.as_ref());
        vec_of_slices2.extend_from_slice(zz);
    });

    vec_of_slices2
        .into_boxed_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("vec_to_boxed_array2: length mismatch outer array"))
}

/// Converts a three-dimensional vector to a constant sized two-dimensional array.
pub fn vec_to_boxed_array3<T: Clone, const N: usize, const M: usize, const K: usize>(
    vec: Vec<Vec<Vec<T>>>,
) -> Box<[[[T; N]; M]; K]> {
    let mut vec_of_slices2: Vec<[[T; N]; M]> = vec![];
    vec.into_iter().for_each(|x| {
        let r: Box<[[T; N]; M]> = vec_to_boxed_array2(x);
        let zz: &[[[T; N]; M]] = std::slice::from_ref(r.as_ref());
        vec_of_slices2.extend_from_slice(zz);
    });

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
        fn vec_to_boxed_array2<T: Clone, const N: usize, const M: usize>(
            vec: Vec<Vec<T>>,
        ) -> Box<[[T; N]; M]> {
            let mut vec_of_slices2: Vec<[T; N]> = vec![];
            vec.into_iter().for_each(|x: Vec<T>| {
                let y: Box<[T]> = x.into_boxed_slice();
                let z: Box<[T; N]> = y
                    .try_into()
                    .unwrap_or_else(|_| panic!("vec_to_boxed_array2: length mismatch inner array"));
                let zz: &[[T; N]] = std::slice::from_ref(z.as_ref());
                vec_of_slices2.extend_from_slice(zz);
            });

            vec_of_slices2
                .into_boxed_slice()
                .try_into()
                .unwrap_or_else(|_| panic!("vec_to_boxed_array2: length mismatch outer array"))
        }

        vec_to_boxed_array2(vec![vec![$val; $len1]; $len2])
    }};
}
