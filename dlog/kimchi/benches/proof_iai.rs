use iai::black_box;
use kimchi::bench::proof;

fn iai_benchmark_short() {
    proof(black_box(20))
}

fn iai_benchmark_long() {
    proof(black_box(30))
}

iai::main!(iai_benchmark_short, iai_benchmark_long);
