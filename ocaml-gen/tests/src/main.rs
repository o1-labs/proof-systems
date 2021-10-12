#![feature(concat_idents)]

use ocaml_gen::{decl_fake_generic, decl_func, decl_module, decl_type, Env};
use ocamlgen_test_stubs::*;
use std::io::Write;

fn main() {
    let mut w = std::io::stdout();
    let env = &mut Env::default();

    decl_fake_generic!(T1, 0);
    decl_fake_generic!(T2, 1);
    decl_fake_generic!(T3, 2);

    write!(
        w,
        "(* This file is generated automatically with ocaml_gen. *)\n"
    )
    .unwrap();

    decl_type!(w, env, SingleTuple => "single_tuple");
    decl_func!(w, env, new => "new_t");
    decl_func!(w, env, print => "print_t");
}
