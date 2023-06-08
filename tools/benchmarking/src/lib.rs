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
    fn function(parameter: usize, data: &Self::RefinedData);
}
