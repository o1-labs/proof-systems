# Mina book

This directory holds the code related to documentation and specifications of the
proof systems.

It is built with [Docusaurus](https://docusaurus.io/).

## Running locally

```console
# Install dependencies
make deps

# Serve the page locally with hot reload
make serve
# Then open http://localhost:3000/proof-systems/ in your browser

# Build for production
make build

# Serve the production build locally
make serve-built

# Clean generated artifacts
make clean
```

The specifications in the book are dynamically generated. Refer to the
[specifications/](specifications/) directory.
