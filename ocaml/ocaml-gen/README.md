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

To allow generation of bindings on structs, use [Struct]():

```rust
#[ocaml_gen::Struct]
struct MyType {
  // ...
}
```

To allow generation of bindings on enums, use [ocaml_gen::Enum]():

```rust
#[ocaml_gen::Enum]
enum MyType {
  // ...
}
```

To allow generation of bindings on functions, use [ocaml_gen::func]():

```rust
#[ocaml_gen::func]
#[ocaml::func] // if you use the crate ocaml-rs' macro, it must appear after
pub fn your_function(arg1: String) {
  //...
}
```

To allow generation of bindings on custom types, use [ocaml_gen::CustomType]():

```rust
#[ocaml_gen::CustomType]
struct MyCustomType {
  // ...
}
```

## Guidance

A few things to keep in mind:

* declaring different types within the same namespace (module) is dangerous. For example, you can shadow a previous type by declaring a new type with the same name. Another example is that you can shadow a record field or tag name if another type has the same record field or tag name.
* If you want to have different types that map to different concrete instantiations of the same generic custom type in Rust, you will have to create different types in Rust.
