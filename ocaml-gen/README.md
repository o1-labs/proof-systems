# Generating bindings

This crate provides automatic generation of OCaml bindings.
Refer to the rustdoc for more information.

## Binding generation

Here's an example of generating some bindings:

```rust
// initialize your environment
let env = &mut Env::default();

// choose where you want to write the bindings
let w = &mut std::io::stdout();

// we need to create fake generic placeholders for generic structs
decl_fake_generic!(T1, 0);
decl_fake_generic!(T2, 1);

// you can declare modules
decl_module!(w, env, "Types", {
    
    // and types
    decl_type!(w, env, SomeType);

    // and even generic types
    decl_type!(w, env, SomeGenericType::<T1>);

    // you can also rename a type
    decl_type!(w, env, SomeOtherGenericType::<T1> => "thing");
});

decl_module!(w, env, "ImportantType", {

    // the OCaml way is often to rename your module's main type as `t`
    decl_type!(w, env, CamlBigInteger256 => "t");

    // you can declare functions as well
    // note that the underlying function calls `caml_of_numeral_to_ocaml`
    // so you have to either import all (e.g. `use path::*`)
    // or you have to import `caml_of_numeral_to_ocaml`
    decl_func!(w, env, caml_of_numeral => "of_numeral");
});
```

## Binding description

To allow the previous example to work, you must derive the correct functions on your types and functions.
To do that, you can use the [ocaml-derive](./derive) crate.

To allow generation of bindings on structs, use [OCamlGen]():

```rust
use ocaml_gen::OcamlGen;

#[OcamlGen]
struct MyType {
  // ...
}
```

To allow generation of bindings on enums, use [OcamlEnum]():

```rust
use ocaml_gen::OcamlEnum;

#[OcamlEnum]
enum MyType {
  // ...
}
```

To allow generation of bindings on functions, use [ocaml_gen]():

```rust
#[ocaml_gen]
#[ocaml::func] // if you use the crate ocaml-rs' macro, it must appear after
pub fn your_function(arg1: String) {
  //...
}
```

To allow generation of bindings on custom types, use [OCamlCustomType]():

```rust
use ocaml_gen::OCamlCustomType;

#[OCamlCustomType]
struct MyCustomType {
  // ...
}
```
