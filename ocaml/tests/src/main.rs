use ocaml_gen::{decl_fake_generic, decl_func, decl_module, decl_type, decl_type_alias, Env};
use ocamlgen_test_stubs::*;

fn main() {
    let mut w = std::io::stdout();
    let env = &mut Env::default();

    // single tuple structs are an edge case
    decl_type!(w, env, SingleTuple => "single_tuple");
    decl_func!(w, env, new => "new_t");
    decl_func!(w, env, print => "print_t");

    // something else
    decl_fake_generic!(T1, 0);

    decl_type!(w, env, SomeType<T1>);
    decl_type!(w, env, SomeConcreteType);

    decl_module!(w, env, "A", {
        decl_type!(w, env, SomeType<SomeConcreteType> => "t2");
        decl_func!(w, env, thing);
    });
}
