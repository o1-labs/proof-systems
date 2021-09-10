use ark_ec::ProjectiveCurve;
use ark_ff::{Field, One, FftField};
use ark_poly::domain::DomainCoeff;
use rayon::prelude::*;
use std::ops::MulAssign;

#[inline]
fn bitreverse(mut n: u32, l: u32) -> u32 {
    let mut r = 0;
    for _ in 0..l {
        r = (r << 1) | (n & 1);
        n >>= 1;
    }
    r
}

fn best_fft<T: DomainCoeff<F>, F: FftField>(
    a: &mut [T],
    omega: F,
    log_n: u32,
    serial_fft: fn(&mut [T], F, u32),
) {
    fn log2_floor(num: usize) -> u32 {
        assert!(num > 0);
        let mut pow = 0;
        while (1 << (pow + 1)) <= num {
            pow += 1;
        }
        pow
    }

    let num_cpus = rayon::current_num_threads();
    let log_cpus = log2_floor(num_cpus);
    if log_n <= log_cpus {
        serial_fft(a, omega, log_n);
    } else {
        parallel_fft(a, omega, log_n, log_cpus, serial_fft);
    }
}

fn parallel_fft<T: DomainCoeff<F>, F: FftField>(
    a: &mut [T],
    omega: F,
    log_n: u32,
    log_cpus: u32,
    serial_fft: fn(&mut [T], F, u32),
) {
    assert!(log_n >= log_cpus);

    let m = a.len();
    let num_chunks = 1 << (log_cpus as usize);
    assert_eq!(m % num_chunks, 0);
    let m_div_num_chunks = m / num_chunks;

    let mut tmp = vec![vec![T::zero(); m_div_num_chunks]; num_chunks];
    let new_omega = omega.pow(&[num_chunks as u64]);
    let new_two_adicity = ark_ff::utils::k_adicity(2, m_div_num_chunks);

    tmp.par_iter_mut().enumerate().for_each(|(j, tmp)| {
        // Shuffle into a sub-FFT
        let omega_j = omega.pow(&[j as u64]);
        let omega_step = omega.pow(&[(j * m_div_num_chunks) as u64]);

        let mut elt = F::one();
        for i in 0..m_div_num_chunks {
            for s in 0..num_chunks {
                let idx = (i + (s * m_div_num_chunks)) % m;
                let mut t = a[idx];
                t *= elt;
                tmp[i] += t;
                elt *= &omega_step;
            }
            elt *= &omega_j;
        }

        // Perform sub-FFT
        serial_fft(tmp, new_omega, new_two_adicity);
    });

    a.iter_mut()
        .enumerate()
        .for_each(|(i, a)| *a = tmp[i % num_chunks][i / num_chunks]);
}

fn serial_group_fft<G: ProjectiveCurve>(a: &mut [G], omega: G::ScalarField, log_n: u32) {
    let n = a.len() as u32;
    assert_eq!(n, 1 << log_n);

    for k in 0..n {
        let rk = bitreverse(k, log_n);
        if k < rk {
            a.swap(rk as usize, k as usize);
        }
    }

    let mut m = 1;
    for _ in 0..log_n {
        let w_m = omega.pow(&[(n / (2 * m)) as u64]);

        let mut k = 0;
        while k < n {
            let mut w = G::ScalarField::one();
            for j in 0..m {
                let mut t = a[(k + j + m) as usize];
                t *= w;
                let mut tmp = a[(k + j) as usize];
                tmp -= t;
                a[(k + j + m) as usize] = tmp;
                a[(k + j) as usize] += t;
                w.mul_assign(&w_m);
            }

            k += 2 * m;
        }

        m *= 2;
    }
}

/// The FFT algorithm for a field F can be performed on vectors whose entries are elements
/// of any F-vector space. The traditional finite-field FFT is when this vector space is
/// F itself.
///
/// But, a group with scalar field F is also an F-vector space, and we can use the FFT algorithm
/// to convert a series of group elements `[g_0, ..., g_{n-1}]`, with `g_i` thought of as
/// a commitment to the polynomial `x^i`, into a series of group elements that correspond to the
/// commitments to the Lagrange basis polynomials over the domain of size n.
pub fn group_fft<G: ProjectiveCurve>(a: &mut [G], omega: G::ScalarField, log_n: u32) {
    best_fft(a, omega, log_n, serial_group_fft::<G>)
}
