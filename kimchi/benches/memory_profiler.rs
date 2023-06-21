use benchmarking::{runner::CriterionBlackBox, Benchmark};
use dhat::{Profiler, ProfilerBuilder};

///an instrumented allocator that allows to collect stats about heap memory, slow
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn your_code_to_profile() {
    //not the best example given that I'm also profiling the set up data
    type C = kimchi::benchmarks::Proving;
    let d = C::prepare_data();
    let d = C::refine_data(12, &d);
    C::function::<CriterionBlackBox>(12, &d);
}
fn main() {
    //profiling starts here
    let profiler = Profiler::builder().build();
    your_code_to_profile();

    // profiling ends here when the profiler is dropped and a file will be created
    // can be visualized here: https://nnethercote.github.io/dh_view/dh_view.html
}
