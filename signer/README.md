# Mina signer

This crate provides an API and framework for Mina signing.  It follows the algorithm outlined in the [Mina Signature Specification](https://github.com/MinaProtocol/mina/blob/master/docs/specs/signatures/description.md).

## Simple interface

The [create] function uses the default signer configuration compatible with mainnet and testnet transaction signatures.

```rust
#[path = "../tests/transaction.rs"]
mod transaction;

use rand;
use mina_signer::{NetworkId, Keypair, PubKey, Signer};
use transaction::Transaction;

let keypair = Keypair::rand(&mut rand::rngs::OsRng);

let tx = Transaction::new_payment(
                keypair.public,
                PubKey::from_address("B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt").expect("invalid receiver address"),
                1729000000000,
                2000000000,
                271828,
            );

let mut ctx = mina_signer::create(NetworkId::TESTNET);
let sig = ctx.sign(keypair, tx);

assert!(ctx.verify(sig, keypair.public, tx));
```

## Advanced interface

The [custom] function allows specification of an alternative cryptographic sponge and parameters, for example, in order to create signatures that can be verified more efficiently using the Kimchi proof system.

```rust
#[path = "../tests/transaction.rs"]
mod transaction;

use rand;
use oracle::{pasta, poseidon, constants};
use mina_signer::{NetworkId, Keypair, PubKey, Signer};
use transaction::Transaction;

let keypair = Keypair::rand(&mut rand::rngs::OsRng);

let tx = Transaction::new_payment(
                keypair.public,
                PubKey::from_address("B62qrKG4Z8hnzZqp1AL8WsQhQYah3quN1qUj3SyfJA8Lw135qWWg1mi").expect("invalid receiver address"),
                1729000000000,
                2000000000,
                271828,
            );

let mut ctx = mina_signer::custom::<constants::PlonkSpongeConstantsKimchi>(
    pasta::fp_kimchi::params(),
    NetworkId::TESTNET,
);

let sig = ctx.sign(keypair, tx);
assert!(ctx.verify(sig, keypair.public, tx));
```

Note that these examples use the test [`Transaction`](https://github.com/o1-labs/proof-systems/tree/master/signer/tests/transaction.rs) structure found in the [`./tests`](https://github.com/o1-labs/proof-systems/tree/master/signer/tests) directory.  This is a complete reference implementation of the Mina payment and delegation transaction structures found on mainnet and testnet.

## Framework

The framework allows you to easily define a new signature type simply by implementing the `Hashable` and `Signable` traits.

For example, if you wanted to create Mina signatures for a `Foo` structure you would do the following.

```rust
use mina_signer::{Hashable, NetworkId, ROInput, Signable};

#[derive(Clone, Copy)]
struct Foo {
    foo: u32,
    bar: u64,
}

impl Hashable for Foo {
    fn to_roinput(self) -> ROInput {
        let mut roi = ROInput::new();

        roi.append_u32(self.foo);
        roi.append_u64(self.bar);

        roi
    }
}

impl Signable for Foo {
    fn domain_string(network_id: NetworkId) -> &'static str {
       match network_id {
           NetworkId::MAINNET => "FooSigMainnet",
           NetworkId::TESTNET => "FooSigTestnet",
       }
   }
}
```

For more details please see the rustdoc mina-signer documentation.

# Unit tests

There is a standard set of [signature unit tests](https://github.com/o1-labs/proof-systems/tree/master/signer/tests/tests.rs) in the [`./tests`](https://github.com/o1-labs/proof-systems/tree/master/signer/tests) directory.

These can be run with

`cargo test --package mina-signer --test tests `
