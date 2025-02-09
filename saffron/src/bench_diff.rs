use ark_ff::UniformRand;
use mina_curves::pasta::Fp;
use rayon::prelude::*;

fn main() {
    // first arg should be the size
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <size>", args[0]);
        std::process::exit(1);
    }
    let size = args[1].parse::<usize>().unwrap();
    let mut rng = rand::thread_rng();
    let n: usize = 1 << size;
    let vec_1: Vec<Fp> = (0..n).map(|_| Fp::rand(&mut rng)).collect::<Vec<Fp>>();
    let vec_2: Vec<Fp> = (0..n).map(|_| Fp::rand(&mut rng)).collect::<Vec<Fp>>();

    // Time for difference
    let start = std::time::Instant::now();
    let _ = vec_1
        .iter()
        .zip(vec_2.iter())
        .map(|(a, b)| a - b)
        .collect::<Vec<Fp>>();
    let elapsed = start.elapsed();
    println!("Time for difference: {:?}", elapsed);

    // Time for difference in parallel using rayon
    let start = std::time::Instant::now();
    let _ = vec_1
        .par_iter()
        .zip(vec_2.par_iter())
        .map(|(a, b)| a - b)
        .collect::<Vec<Fp>>();
    let elapsed = start.elapsed();
    println!("Time for difference in parallel: {:?}", elapsed);
}
