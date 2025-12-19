//! This module provides different helpers in creating constant sized
//! arrays and converting them to different formats.
//!
//! Functions in this module are not necessarily optimal in terms of
//! allocations, as they tend to create intermediate vectors. For
//! better performance, either optimise this code, or use
//! (non-fixed-sized) vectors.

#[cfg(feature = "no-std")]
use alloc::{boxed::Box, vec, vec::Vec};

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
        let zz: &[[T; N]] = core::slice::from_ref(z.as_ref());
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
        let zz: &[[[T; N]; M]] = core::slice::from_ref(r.as_ref());
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
                let zz: &[[T; N]] = core::slice::from_ref(z.as_ref());
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

#[cfg(test)]
mod tests {
    use super::*;

    use ark_ec::AffineRepr;
    use ark_ff::{UniformRand, Zero};
    use mina_curves::pasta::Pallas as CurvePoint;

    pub type BaseField = <CurvePoint as AffineRepr>::BaseField;

    #[test]
    /// Tests whether initialising different arrays creates a stack
    /// overflow. The usual default size of the stack is 128kB.
    fn test_boxed_stack_overflow() {
        // Each field element is assumed to be 256 bits, so 1.000.000
        // elements is 30MB. This often overflows the stack if created
        // as an array.
        let _boxed: Box<[[BaseField; 1000000]; 1]> =
            vec_to_boxed_array2(vec![vec![BaseField::zero(); 1000000]; 1]);
        let _boxed: Box<[[BaseField; 250000]; 4]> =
            vec_to_boxed_array2(vec![vec![BaseField::zero(); 250000]; 4]);
        let _boxed: Box<[BaseField; 1000000]> = box_array![BaseField::zero(); 1000000];
        let _boxed: Box<[[BaseField; 250000]; 4]> = box_array2![BaseField::zero(); 250000; 4];
    }

    #[test]
    /// Tests whether boxed array tranformations preserve the elements.
    fn test_boxed_stack_completeness() {
        let mut rng = crate::tests::make_test_rng(None);

        const ARR_SIZE: usize = 100;

        let vector1: Vec<usize> = (0..ARR_SIZE).map(|i| i * i).collect();
        let boxed1: Box<[usize; ARR_SIZE]> = vec_to_boxed_array(vector1);
        assert!(boxed1[0] == 0);
        assert!(boxed1[ARR_SIZE - 1] == (ARR_SIZE - 1) * (ARR_SIZE - 1));
        let n_queries = ARR_SIZE;
        for _ in 0..n_queries {
            let index = usize::rand(&mut rng) % ARR_SIZE;
            assert!(boxed1[index] == index * index);
        }

        let vector2: Vec<Vec<usize>> = (0..ARR_SIZE)
            .map(|i| (0..ARR_SIZE).map(|j| i * j).collect())
            .collect();
        let boxed2: Box<[[usize; ARR_SIZE]; ARR_SIZE]> = vec_to_boxed_array2(vector2);
        assert!(boxed2[0][0] == 0);
        assert!(boxed2[ARR_SIZE - 1][ARR_SIZE - 1] == (ARR_SIZE - 1) * (ARR_SIZE - 1));
        let n_queries = ARR_SIZE;
        for _ in 0..n_queries {
            let index1 = usize::rand(&mut rng) % ARR_SIZE;
            let index2 = usize::rand(&mut rng) % ARR_SIZE;
            assert!(boxed2[index1][index2] == index1 * index2);
        }

        let vector3: Vec<Vec<Vec<usize>>> = (0..ARR_SIZE)
            .map(|i| {
                (0..ARR_SIZE)
                    .map(|j| (0..ARR_SIZE).map(|k| i * j + k).collect())
                    .collect()
            })
            .collect();
        let boxed3: Box<[[[usize; ARR_SIZE]; ARR_SIZE]; ARR_SIZE]> = vec_to_boxed_array3(vector3);
        assert!(boxed3[0][0][0] == 0);
        assert!(
            boxed3[ARR_SIZE - 1][ARR_SIZE - 1][ARR_SIZE - 1]
                == (ARR_SIZE - 1) * (ARR_SIZE - 1) + (ARR_SIZE - 1)
        );
        let n_queries = ARR_SIZE;
        for _ in 0..n_queries {
            let index1 = usize::rand(&mut rng) % ARR_SIZE;
            let index2 = usize::rand(&mut rng) % ARR_SIZE;
            let index3 = usize::rand(&mut rng) % ARR_SIZE;
            assert!(boxed3[index1][index2][index3] == index1 * index2 + index3);
        }
    }
}
