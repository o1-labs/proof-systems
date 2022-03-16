# Mina crypto

This crate provides an API and framework for Mina hashing and signing.

* The [hasher](crate::hasher) is a safe wrapper around Mina's instances of the [Poseidon arithmetic sponge](https://github.com/o1-labs/cryptography-rfcs/blob/master/mina/001-poseidon-sponge.md)
* The [signer](crate::signer) follows the algorithm outlined in the [Mina Signature Specification](https://github.com/MinaProtocol/mina/blob/master/docs/specs/signatures/description.md)

## Hasher interface

The `hasher` module currently supports creating both legacy and an experimental kimchi hashers.

* [`hasher::create_legacy`] create a legacy hasher
* [`hasher::create_kimchi`] create an experimental kimchi hasher

Here is an example of how to use the hasher interface.

```rust
use mina_crypto::hasher::{create_legacy, Hashable, Hasher, ROInput};

#[derive(Clone)]
struct Example {
    x: u32,
    y: u64,
}

impl Hashable for Example {
    type D = u32;

    fn to_roinput(self) -> ROInput {
        let mut roi = ROInput::new();
        roi.append_u32(self.x);
        roi.append_u64(self.y);
        roi
    }

    fn domain_string(_: Option<Self>, seed: &u32) -> Option<String> {
        format!("Example {}", seed).into()
    }
}

// Usage 1: incremental interface
let mut hasher = create_legacy::<Example>(0);
hasher.update(Example { x: 82, y: 834 });
hasher.update(Example { x: 1235, y: 93 });
let out = hasher.digest();
hasher.init(1);
hasher.update(Example { x: 82, y: 834 });
let out = hasher.digest();

// Usage 2: builder interface with one-shot pattern
let mut hasher = create_legacy::<Example>(0);
let out = hasher.update(Example { x: 3, y: 1 }).digest();
let out = hasher.update(Example { x: 31, y: 21 }).digest();

// Usage 3: builder interface with one-shot pattern also setting init state
let mut hasher = create_legacy::<Example>(0);
let out = hasher.init(0).update(Example { x: 3, y: 1 }).digest();
let out = hasher.init(1).update(Example { x: 82, y: 834 }).digest();

// Usage 4: one-shot interfaces
let mut hasher = create_legacy::<Example>(0);
let out = hasher.hash(Example { x: 3, y: 1 });
let out = hasher.init_and_hash(1, Example { x: 82, y: 834 });
```


## Signer interface

The `signer` module currently supports creating both legacy and an experimental kimchi signers.

* [`signer::create_legacy`] create a legacy signer compatible with mainnet and testnet transaction signatures
* [`signer::create_kimchi`] create an experimental kimchi signer

Here is an example of how to use the signer interface to sign and verify Mina transactions.

```rust
#[path = "../tests/transaction.rs"]
mod transaction;

use rand;
use mina_crypto::signer::{NetworkId, Keypair, PubKey, Signer};
use transaction::Transaction;

let keypair = Keypair::rand(&mut rand::rngs::OsRng);

let tx = Transaction::new_payment(
                keypair.public,
                PubKey::from_address("B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt").expect("invalid receiver address"),
                1729000000000,
                2000000000,
                271828,
            );

let mut ctx = mina_crypto::signer::create_legacy::<Transaction>(NetworkId::TESTNET);
let sig = ctx.sign(keypair, tx);
assert!(ctx.verify(sig, keypair.public,tx));
```

Note that these examples use the test [`Transaction`](https://github.com/o1-labs/proof-systems/tree/master/crypto/tests/transaction.rs) structure found in the [`./tests`](https://github.com/o1-labs/proof-systems/tree/master/crypto/tests) directory.  This is a complete reference implementation of the Mina payment and delegation transaction structures found on mainnet and testnet.

## The `Hashable` trait

In order to sign something it must be hashed.  This framework allows you to define how types are hashed by implementing the [`Hashable`](crate::hasher::Hashable) trait.

For example, if you wanted to create Mina signatures for a `Foo` structure you would do the following.

```rust
use mina_crypto::{
    hasher::{Hashable, ROInput},
    signer::NetworkId,
};

#[derive(Clone)]
struct Foo {
    foo: u32,
    bar: u64,
}

impl Hashable for Foo {
    type D = NetworkId;

    fn to_roinput(self) -> ROInput {
        let mut roi = ROInput::new();

        roi.append_u32(self.foo);
        roi.append_u64(self.bar);

        roi
    }

    fn domain_string(this: Option<Self>, network_id: &NetworkId) -> Option<String> {
       match network_id {
           NetworkId::MAINNET => "FooSigMainnet",
           NetworkId::TESTNET => "FooSigTestnet",
       }
       .to_string()
       .into()
    }
}
```

**Example: `domain_string` parameterized by structure contents**

Suppose you wanted to hash a non-leaf Merkle tree node, where the
domain string depends on the height of the node.  This can be implemented like this.

```rust
use mina_crypto::{
    hasher::{Hashable, ROInput},
    signer::{NetworkId, ScalarField},
};

#[derive(Clone)]
struct ExampleMerkleNode {
    height: u64,
    left: ScalarField,
    right: ScalarField,
}

impl Hashable for ExampleMerkleNode {
    type D = ();

    fn to_roinput(self) -> ROInput {
        let mut roi = ROInput::new();

        roi.append_scalar(self.left);
        roi.append_scalar(self.right);

        roi
    }

    fn domain_string(this: Option<Self>, _: &Self::D) -> Option<String> {
        match this {
            None => panic!("missing this argument (should never happen)"),
            Some(x) => format!("ExampleMerkleNode{:03}", x.height).into(),
        }
    }
}

// // Called like this...
// let mut hasher = create_legacy::<ExampleMerkleNode>(0);
// let out = hasher.hash(node_21);
// // Or this..
// let out = hasher.update(node_15).digest();
```

**Example: `domain_string` parameterized by `domain_param`**

If the height is not part of the structure, but instead a parameter
passed when hashing, then it can be implemented like this.

```rust
use mina_crypto::{
    hasher::{Hashable, ROInput},
};
use mina_curves::pasta::Fp;

#[derive(Clone)]
struct ExampleMerkleNode {
    left: Fp,
    right: Fp,
}

impl Hashable for ExampleMerkleNode {
    type D = u64;

    fn to_roinput(self) -> ROInput {
        let mut roi = ROInput::new();

        roi.append_field(self.left);
        roi.append_field(self.right);

        roi
    }

    fn domain_string(_: Option<Self>, height: &Self::D) -> Option<String> {
        format!("MerkleTree{:03}", height).into()
    }
}

// // Called like this...
// let mut hasher = create_legacy::<ExampleMerkleNode>(0);
// let out = hasher.init_and_hash(7 /* height */, node_21);
// let out = hasher.init_and_hash(3 /* height */, node_15);
// // Or this..
// let out = hasher.init(7).update(node_21).digest();
// let out = hasher.init(3).update(node_15).digest();
```

**Combining `ROInput`s**

When implementing the `Hashable` trait for a structure composed of other `Hashable`
structures, the `to_roinput()` implementation needs to combine `ROInput`s.

Here is an example showing how this is done.

```rust
use mina_crypto::{
    hasher::{Hashable, ROInput},
};

#[derive(Clone)]
struct A {
    x: u32,
    y: u32,
}

impl Hashable for A {
    type D = ();

    fn to_roinput(self) -> ROInput {
        let mut roi = ROInput::new();
        roi.append_u32(self.x);
        roi.append_u32(self.y);
        roi
    }

    fn domain_string(_: Option<Self>, _: &Self::D) -> Option<String> {
        format!("A").into()
    }
}

#[derive(Clone)]
struct B {
    a1: A,
    a2: A,
    z: u32,
}

impl Hashable for B {
    type D = ();

    fn to_roinput(self) -> ROInput {
        let mut roi = ROInput::new();
        // Way 1: Append Hashable input
        roi.append_hashable(self.a1);
        // Way 2: Append ROInput
        roi.append_roinput(self.a2.to_roinput());
        roi.append_u32(self.z);
        roi
    }

    fn domain_string(_: Option<Self>, _: &Self::D) -> Option<String> {
        format!("B").into()
    }
}
```

For more details please see the rustdoc mina-crypto documentation.

# Tests

There is a standard set of [signature tests](https://github.com/o1-labs/proof-systems/tree/master/crypto/tests/signer.rs) in the [`./tests`](https://github.com/o1-labs/proof-systems/tree/master/crypto/tests) directory.

These can be run with

`cargo test --package mina-crypto`
