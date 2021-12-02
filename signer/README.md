# Mina signer

This crate provides an API and framework for Mina signing.  It follows the algorithm outlined in the [Mina Signature Specification](https://github.com/MinaProtocol/mina/blob/develop/docs/specs/signatures/description.md).

## Simple interface

The simple interface uses the default signer configuration compatible with mainnet and testnet transaction signatures.

```rust
use rand;
use mina_signer::{NetworkId, Keypair, Signer};
use mina_signer::NetworkId;

let mut ctx = mina_signer::create(NetworkId::TESTNET);
let sig = ctx.sign(key_pair, transaction);

assert_eq!(ctx.verify(sig, key_pair.public, transaction), true);
```

## Advanced interface

The advanced interface allows specification of an alternative cryptographic sponge and parameters, for example, in order to create signatures that can be verified more efficiently using the Kimchi proof system.

```rust
use rand;
use mina_signer::{NetworkId, Keypair, Signer};
use oracle::{pasta, poseidon};

let mut ctx = mina_signer::custom::<poseidon::PlonkSpongeConstants5W>(
    pasta::fp5::params(),
    NetworkId::TESTNET,
);

let sig = ctx.sign(key_pair, transaction);
assert_eq!(ctx.verify(sig, key_pair.public, transaction), true);
```

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

There is a standard set of signature unit tests in the `./tests` directory.

These can be run with

`cargo test --package mina-signer --test tests `