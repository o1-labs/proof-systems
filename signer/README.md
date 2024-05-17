# Mina signer

This crate provides an API and framework for Mina signing.  It follows the algorithm outlined in the [Mina Signature Specification](https://github.com/MinaProtocol/mina/blob/master/docs/specs/signatures/description.md).

## Signer interface

The `mina_signer` crate currently supports creating both legacy and an experimental kimchi signers.

* [`create_legacy`] creates a legacy signer compatible with mainnet and testnet transaction signatures
* [`create_kimchi`] creates an experimental kimchi signer

Here is an example of how to use the signer interface to sign and verify Mina transactions.

```rust
#[path = "../tests/transaction.rs"]
mod transaction;

use rand;
use mina_signer::{NetworkId, Keypair, PubKey, Signer};
use transaction::Transaction;

let keypair = Keypair::rand(&mut rand::rngs::OsRng).expect("failed to generate keypair");

let tx = Transaction::new_payment(
                keypair.public.clone(),
                PubKey::from_address("B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt").expect("invalid receiver address"),
                1729000000000,
                2000000000,
                271828,
            );

let mut ctx = mina_signer::create_legacy::<Transaction>(NetworkId::TESTNET);
let sig = ctx.sign(&keypair, &tx);
assert!(ctx.verify(&sig, &keypair.public, &tx));
```

These examples use the test [`Transaction`](https://github.com/o1-labs/proof-systems/tree/master/signer/tests/transaction.rs) structure found in the [`./tests`](https://github.com/o1-labs/proof-systems/tree/master/signer/tests) directory.  This is a complete reference implementation of the Mina payment and delegation transaction structures found on mainnet and testnet.

**Note:** In order to sign something it must be hashed.  This framework allows you to define how types are hashed by implementing the [`Hashable`](mina_hasher::Hashable) trait-- see the [`mina_hasher`](mina_hasher) documentation

For more details about the ``mina_signer`, please see rustdoc mina-signer documentation.

# Tests

There is a standard set of [signature tests](https://github.com/o1-labs/proof-systems/tree/master/signer/tests/signer.rs) in the [`./tests`](https://github.com/o1-labs/proof-systems/tree/master/signer/tests) directory.

These can be run with

`cargo test --package mina-signer`
