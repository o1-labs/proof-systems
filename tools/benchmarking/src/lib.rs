/// Represents a measurement agnostic benchmark, implement this trait for an empty struct
/// and the type can be used in any place that runs [Benchmark]s, ideally by just adding
/// a line like this:
/// ```rust,ignore
///  let benches = benches.add::<MyBenchmark>();
/// ```
pub trait Benchmark {
    type Data;
    type RefinedData;

    ///initialized some data to be used by the benchmarked function
    fn prepare_data() -> Self::Data;

    ///refine the data to be used with an specific parameter
    fn refine_data(parameter: usize, data: &Self::Data) -> Self::RefinedData;

    ///recommended parameters to run this benchmark
    fn default_parameters() -> Option<Vec<usize>>;
    ///some function to benchmark
    fn function<B: BlackBox>(parameter: usize, data: &Self::RefinedData);
}

/// a black box, to prevent compiler from optimizing things away
pub trait BlackBox {
    fn black_box<T>(dummy: T) -> T;
}

///tries to get params from env var PARAMS
pub fn params() -> Option<Vec<usize>> {
    match std::env::var("PARAMS") {
        Ok(var) => Some(
            (*var)
                .split(',')
                .map(|x| x.trim().parse::<usize>().unwrap())
                .collect(),
        ),
        _ => None,
    }
}

#[cfg(feature = "criterion")]
///reusable traits and types to implement new measurements
pub mod runner {
    use crate::{Benchmark, BlackBox};
    use criterion::{measurement::Measurement, BenchmarkGroup, Criterion};
    use std::marker::PhantomData;
    pub trait Benchmarks<M: Measurement> {
        fn run(c: &mut Criterion<M>, params: &Option<Vec<usize>>);
    }
    impl<M: Measurement> Benchmarks<M> for () {
        fn run(_c: &mut Criterion<M>, _params: &Option<Vec<usize>>) {}
    }

    pub struct CriterionBlackBox;
    impl BlackBox for CriterionBlackBox {
        fn black_box<T>(dummy: T) -> T {
            criterion::black_box(dummy)
        }
    }
    pub trait BenchmarkRunner {
        type Measurement: Measurement;
        const NAME: &'static str;
        fn bench<H: Benchmark>(
            group: &mut BenchmarkGroup<'_, Self::Measurement>,
            p: usize,
            data: H::RefinedData,
        );
        ///prints a message with some explanation
        fn message(params: &Option<Vec<usize>>) {
            println!("\n");
            match params {
                Some(_) => {
                    println!("Running {} benchmarks with selected parameters", Self::NAME);
                }
                None => {
                    println!("Running {} benchmarks with default parameters", Self::NAME);
                }
            }
            println!("You can run specific benchmarks and with custom parameters in the next way:");
            println!(
                "PARAMS=6,8,10 cargo criterion --bench {} -- Proving",
                Self::NAME
            );
            println!("\n");
        }
    }

    pub struct AddBenchmark<R: BenchmarkRunner, H: Benchmark, T: Benchmarks<R::Measurement>>(
        PhantomData<(R, H, T)>,
    );
    impl<H: Benchmark, T: Benchmarks<R::Measurement>, R: BenchmarkRunner> Benchmarks<R::Measurement>
        for AddBenchmark<R, H, T>
    {
        fn run(c: &mut Criterion<R::Measurement>, params: &Option<Vec<usize>>) {
            T::run(c, params);

            // run self
            let data = H::prepare_data();

            let parameters = H::default_parameters().unwrap_or(vec![8, 9, 10, 12, 14, 16]);
            //override with user provided params
            let parameters = params.as_ref().unwrap_or(&parameters);
            //bench it
            {
                let mut group =
                    c.benchmark_group(format!("{}/{}", R::NAME, std::any::type_name::<H>()));
                group.sample_size(10);

                for p in parameters {
                    let data = H::refine_data(*p, &data);

                    R::bench::<H>(&mut group, *p, data);
                }
            }
        }
    }
    impl<H: Benchmark, R: BenchmarkRunner, T: Benchmarks<R::Measurement>> AddBenchmark<R, H, T> {
        pub fn add<N: Benchmark>(self) -> AddBenchmark<R, N, Self> {
            AddBenchmark(PhantomData)
        }
        pub fn run(&self, c: &mut Criterion<R::Measurement>, params: &Option<Vec<usize>>) {
            <Self as Benchmarks<R::Measurement>>::run(c, params)
        }
    }
    pub fn new_benchmark<R: BenchmarkRunner, B: Benchmark>() -> AddBenchmark<R, B, ()> {
        AddBenchmark(PhantomData)
    }
}
