use ocaml_gen::{decl_fake_generic, decl_func, decl_module, decl_type, decl_type_alias, Env};
use ocamlgen_test_stubs::{single_tuple::*, type_alias::*};

fn main() {
    let mut w = std::io::stdout();
    let mut env = Env::default();

    single_tuple(&mut w, &mut env);
    type_alias(&mut w, &mut env);
}

/// testing the single tuple edge-case
/// this should compile to single_tuple = { inner: string } instead of single_tuple = string
fn single_tuple(mut w: impl std::io::Write, env: &mut Env) {
    decl_type!(w, env, SingleTuple);

    decl_func!(w, env, new => "new_t");

    decl_func!(w, env, print => "print_t");
}

/// Testing renaming/relocation of type aliases
fn type_alias(mut w: impl std::io::Write, env: &mut Env) {
    // something else
    decl_fake_generic!(T1, 0);

    decl_type!(w, env, SomeType<T1>);

    decl_type!(w, env, SomeConcreteType);

    decl_module!(w, env, "A", {
        // type t2 = some_concrete_type some_type
        decl_type_alias!(w, env, "t2" => SomeType<SomeConcreteType>);

        decl_func!(w, env, thing);
    });
}
