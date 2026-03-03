# Mina Transaction Types

A `no_std` compatible crate providing Mina Protocol transaction type
definitions.

This crate is designed for use by external projects (e.g., hardware wallets,
WASM environments) that need access to Mina transaction types without requiring
the full ledger crate's dependencies.

## Features

- `no_std` compatible for embedded/constrained environments
- Transaction types: `Coinbase`, `CoinbaseFeeTransfer`
- Currency types: `Amount`, `Fee`, `Signed<T>`, `Sign`

## References

- [zkApp Signing RFC](https://mina-rust.o1labs.org/researchers/zkapp-signing)
- [Mina Protocol Documentation](https://docs.minaprotocol.com)
