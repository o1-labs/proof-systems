# Terminology

This document is intended primarily to communicate mathematical ideas to
programmers with some experience of math.

To that end, we will often be ambivalent about the difference between sets and
types (in whatever programming language, but usually I am imagining some
idealized form of Rust or OCaml). So for example we may write

- $A$ is a type

- $A$ is a set

- `A` is a type

and these should all be interpreted the same way, assuming it makes sense in the
context. Similarly, we may write either of the following, and potentially mean
the same thing:

- $a \colon A$

- $a \in A$

- `a : A`

We use

- $\to$ for function types
- $\mapsto$ for defining functions

Also, we usually assume functions are computed by a program (in whatever sense
of "program" makes sense in the given context). So if we say "let
$f \colon A \to B$", we typically mean that

- $A$ and $B$ are types in some programming language which makes sense in the
  context (or maybe that they are sets, again depending on context)

- $f$ is actually a program computing a function of the type $A \to B$ (again,
  in whatever sense of program makes sense in context)
