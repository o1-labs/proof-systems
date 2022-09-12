use ocaml_gen::{decl_func, decl_module, decl_type, decl_type_alias, Env};
use ocamlgen_test_stubs::*;

fn main() {
    let mut w = std::io::stdout();
    let env = &mut Env::default();

    decl_type!(w, env, SingleTuple => "single_tuple");
    decl_func!(w, env, new => "new_t");
    decl_func!(w, env, print => "print_t");

    decl_module!(w, env, "Car", {
        decl_type!(w, env, Car => "t");
    });

    decl_module!(w, env, "Toyota", {
        decl_type_alias!(w, env, "t" => Car);
        decl_func!(w, env, create_toyota => "create_toyota");
    });
}
