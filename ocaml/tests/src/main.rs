use ocaml_gen::{decl_func, decl_type, Env};
use ocamlgen_test_stubs::*;

fn main() {
    let mut w = std::io::stdout();
    let env = &mut Env::default();

    decl_type!(w, env, SingleTuple => "single_tuple");
    decl_func!(w, env, new => "new_t");
    decl_func!(w, env, print => "print_t");
}
