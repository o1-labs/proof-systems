# Mina crypto

This crate provides an API and framework for Mina signing.  It follows the algorithm outlined in the [Mina Signature Specification](https://github.com/MinaProtocol/mina/blob/master/docs/specs/signatures/description.md).

## Legacy interface

The [create_legacy] function uses the default signer configuration compatible with mainnet and testnet transaction signatures.

```rust
#[path = "../../tests/transaction.rs"]
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

let mut ctx = mina_crypto::signer::create_legacy::<NetworkId>(NetworkId::TESTNET);
let sig = ctx.sign(keypair, tx);
assert!(ctx.verify(sig, keypair.public,tx));
```

## Custom interface

The [create_custom] function allows specification of an alternative cryptographic sponge and parameters, for example, in order to create signatures that can be verified more efficiently using the Kimchi proof system.

```rust
#[path = "../../tests/transaction.rs"]
mod transaction;

use rand;
use oracle::{pasta, poseidon};
use mina_crypto::signer::{NetworkId, Keypair, PubKey, Signer};
use transaction::Transaction;

let keypair = Keypair::rand(&mut rand::rngs::OsRng);

let tx = Transaction::new_payment(
                keypair.public,
                PubKey::from_address("B62qrKG4Z8hnzZqp1AL8WsQhQYah3quN1qUj3SyfJA8Lw135qWWg1mi").expect("invalid receiver address"),
                1729000000000,
                2000000000,
                271828,
            );

let mut ctx = mina_crypto::signer::create_custom::<poseidon::PlonkSpongeConstants15W, NetworkId>(
    pasta::fp::params(),
    NetworkId::TESTNET,
);

let sig = ctx.sign(keypair, tx);
assert!(ctx.verify(sig, keypair.public, tx));
```

Note that these examples use the test [`Transaction`](https://github.com/o1-labs/proof-systems/tree/master/signer/tests/transaction.rs) structure found in the [`./tests`](https://github.com/o1-labs/proof-systems/tree/master/signer/tests) directory.  This is a complete reference implementation of the Mina payment and delegation transaction structures found on mainnet and testnet.

## Framework

In order to sign something it must be hashed.  This framework allows you to define how types are hashed by implementing the `Hashable` trait.

For example, if you wanted to create Mina signatures for a `Foo` structure you would do the following.

```rust
use mina_crypto::{
    hasher::ROInput,
    signer::{Hashable, NetworkId}
    };

#[derive(Clone, Copy)]
struct Foo {
    foo: u32,
    bar: u64,
}

impl Hashable<NetworkId> for Foo {
    fn to_roinput(self) -> ROInput {
        let mut roi = ROInput::new();

        roi.append_u32(self.foo);
        roi.append_u64(self.bar);

        roi
    }

    fn domain_string(self, network_id: &NetworkId) -> String {
       match network_id {
           NetworkId::MAINNET => "FooSigMainnet",
           NetworkId::TESTNET => "FooSigTestnet",
       }.to_string()
    }
}
```

Anything signable must implement the `Hashable` trait with the `Generic` associated type set to `NetworkId`.

Sometimes may wish to hash something so that the domain string is not dependent on the network id.  This structure will not be signable, but it will still be hashable.

For example, suppose you wanted to hash a non-leaf Merkle tree node, where the domain string depends on the height of the node.

```rust
use mina_crypto::{hasher::ROInput, signer::{Hashable, NetworkId, ScalarField}};

#[derive(Clone, Copy)]
struct MerkleIndexNode {
    height: u64,
    left: ScalarField,
    right: ScalarField,
}

impl Hashable<u64> for MerkleIndexNode {
    fn to_roinput(self) -> ROInput {
        let mut roi = ROInput::new();

        roi.append_scalar(self.left);
        roi.append_scalar(self.right);

        roi
    }

    fn domain_string(self, height: &u64) -> String {
        format!("MerkleTree{:03}", height)
    }
}
```

For more details please see the rustdoc mina-signer documentation.

# Unit tests

There is a standard set of [signature unit tests](https://github.com/o1-labs/proof-systems/tree/master/signer/tests/tests.rs) in the [`./tests`](https://github.com/o1-labs/proof-systems/tree/master/signer/tests) directory.

These can be run with

`cargo test --package mina-signer --test tests `
