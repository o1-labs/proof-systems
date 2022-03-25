# Mina hasher

This crate provides an API and framework for Mina hashing. It is a safe wrapper around Mina's instances of the [Poseidon arithmetic sponge](https://github.com/o1-labs/cryptography-rfcs/blob/master/mina/001-poseidon-sponge.md) that converts it from a sponge into a hash interface.

## Hasher interface

The `mina_hasher` crate currently supports creating both the legacy hasher and an experimental kimchi hasher.

- [`create_legacy`] create a legacy hasher
- [`create_kimchi`] create an experimental kimchi hasher

Here is an example of how to use the hasher interface.

```rust
use mina_hasher::{create_legacy, Hashable, Hasher, ROInput};

#[derive(Clone)]
struct Example {
    x: u32,
    y: u64,
}

impl Hashable for Example {
    type D = u32;

    fn to_roinput(&self) -> ROInput {
        let mut roi = ROInput::new();
        roi.append_u32(self.x);
        roi.append_u64(self.y);
        roi
    }

    fn domain_string(_: Option<&Self>, seed: u32) -> Option<String> {
        format!("Example {}", seed).into()
    }
}

// Usage 1: incremental interface
let mut hasher = create_legacy::<Example>(0);
hasher.update(&Example { x: 82, y: 834 });
hasher.update(&Example { x: 1235, y: 93 });
let out = hasher.digest();
hasher.init(1);
hasher.update(&Example { x: 82, y: 834 });
let out = hasher.digest();

// Usage 2: builder interface with one-shot pattern
let mut hasher = create_legacy::<Example>(0);
let out = hasher.update(&Example { x: 3, y: 1 }).digest();
let out = hasher.update(&Example { x: 31, y: 21 }).digest();

// Usage 3: builder interface with one-shot pattern also setting init state
let mut hasher = create_legacy::<Example>(0);
let out = hasher.init(0).update(&Example { x: 3, y: 1 }).digest();
let out = hasher.init(1).update(&Example { x: 82, y: 834 }).digest();

// Usage 4: one-shot interfaces
let mut hasher = create_legacy::<Example>(0);
let out = hasher.hash(&Example { x: 3, y: 1 });
let out = hasher.init_and_hash(1, &Example { x: 82, y: 834 });
```

## The `Hashable` trait

In order to sign something it must be hashed. This framework allows you to define how types are hashed by implementing the [`Hashable`] trait.

For example, if you wanted to create Mina signatures for a `Foo` structure you would do the following.

```rust
use mina_hasher::{Hashable, ROInput};

#[derive(Clone)]
struct Foo {
    foo: u32,
    bar: u64,
}

impl Hashable for Foo {
    type D = ();

    fn to_roinput(&self) -> ROInput {
        let mut roi = ROInput::new();

        roi.append_u32(self.foo);
        roi.append_u64(self.bar);

        roi
    }

    fn domain_string(_this_: Option<&Self>, _: Self::D) -> Option<String> {
        format!("Foo").into()
    }
}
```

**Example: `domain_string` parameterized by structure contents**

Suppose you wanted to hash a non-leaf Merkle tree node, where the
domain string depends on the height of the node. This can be implemented like this.

```rust
use ark_ff::Zero;
use mina_hasher::{create_legacy, Hash, Hashable, Hasher, ROInput};

#[derive(Clone)]
struct ExampleMerkleNode {
    height: u64,
    left: Hash,
    right: Hash,
}

impl Hashable for ExampleMerkleNode {
    type D = ();

    fn to_roinput(&self) -> ROInput {
        let mut roi = ROInput::new();

        roi.append_field(self.left);
        roi.append_field(self.right);

        roi
    }

    fn domain_string(this: Option<&Self>, _: Self::D) -> Option<String> {
        match this {
            None => format!("Unused").into(),
            Some(x) => format!("ExampleMerkleNode{:03}", x.height).into(),
        }
    }
}

// Used like this
let mut hasher = create_legacy::<ExampleMerkleNode>(());
let node = ExampleMerkleNode {
    height: 3,
    left: Hash::zero(),
    right: Hash::zero(),
};
let out = hasher.hash(&node);
// Or like this..
let out = hasher.update(&node).digest();
```

**Example: `domain_string` parameterized by `domain_param`**

If the height is not part of the structure, but instead a parameter
passed when hashing, then it can be implemented like this.

```rust
use ark_ff::Zero;
use mina_hasher::{create_legacy, Hash, Hashable, Hasher, ROInput};

#[derive(Clone)]
struct ExampleMerkleNode {
    left: Hash,
    right: Hash,
}

impl Hashable for ExampleMerkleNode {
    type D = u64;

    fn to_roinput(&self) -> ROInput {
        let mut roi = ROInput::new();

        roi.append_field(self.left);
        roi.append_field(self.right);

        roi
    }

    fn domain_string(_: Option<&Self>, height: Self::D) -> Option<String> {
        format!("MerkleTree{:03}", height).into()
    }
}

// Used like this
let mut hasher = create_legacy::<ExampleMerkleNode>(0);
let node1 = ExampleMerkleNode {
    left: Hash::zero(),
    right: Hash::zero(),
};
let node2 = ExampleMerkleNode {
    left: Hash::zero(),
    right: Hash::zero(),
};
let out = hasher.init_and_hash(3 /* height */, &node1);
let out = hasher.init_and_hash(7 /* height */, &node2);
// Or like this..
let out = hasher.init(3).update(&node1).digest();
let out = hasher.init(7).update(&node2).digest();
```

**Combining `ROInput`s**

When implementing the `Hashable` trait for a structure composed of other `Hashable`
structures, the `to_roinput()` implementation needs to combine `ROInput`s.

Here is an example showing how this is done.

```rust
use mina_hasher::{Hashable, ROInput};

#[derive(Clone, Copy)]
struct A {
    x: u32,
    y: u32,
}

impl Hashable for A {
    type D = ();

    fn to_roinput(&self) -> ROInput {
        let mut roi = ROInput::new();
        roi.append_u32(self.x);
        roi.append_u32(self.y);
        roi
    }

    fn domain_string(_: Option<&Self>, _: Self::D) -> Option<String> {
        format!("A").into()
    }
}

#[derive(Clone, Copy)]
struct B {
    a1: A,
    a2: A,
    z: u32,
}

impl Hashable for B {
    type D = ();

    fn to_roinput(&self) -> ROInput {
        let mut roi = ROInput::new();
        // Way 1: Append Hashable input
        roi.append_hashable(self.a1);
        // Way 2: Append ROInput
        roi.append_roinput(self.a2.to_roinput());
        roi.append_u32(self.z);
        roi
    }

    fn domain_string(_: Option<&Self>, _: Self::D) -> Option<String> {
        format!("B").into()
    }
}
```

For more details please see the rustdoc mina-hasher documentation.

# Tests

There is a standard set of [hasher tests](https://github.com/o1-labs/proof-systems/tree/master/hasher/tests/hasher.rs) in the [`./tests`](https://github.com/o1-labs/proof-systems/tree/master/hasher/tests) directory.

These can be run with

`cargo test --package mina-hasher`
