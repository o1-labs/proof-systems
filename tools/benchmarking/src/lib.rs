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
