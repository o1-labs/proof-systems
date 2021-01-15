This branch contains Plonk protocol implementation which is adapted to run as WebAssembly within Safari (or Chrome) browser. This provides an example of building the Plonk setup/prove/verify protocol tests as wasm module running within the browser. The function exercised here consists of the following two tests:

1. turbo_plonk
   This runs Plonk setup/prove/verify protocols for a circuit consisting of all the supported (generic and custom) constraints
2. poseidon_tweedledee
   This runs Plonk setup/prove/verify protocols for a circuit of 2^13 depth and consisting of Poseidon custom constraints

TOOLCHAIN INSTALLATION

1. Install standard Rust tools rustup, rustc, and carg
2. wasm-pac
   For the installation of this build tool, follow https://rustwasm.github.io/docs/book/game-of-life/setup.html
3. cargo install wasm-bindgen-cli --vers "0.2.69"

BUILDING/RUNNING TEST WITHIN BROWSER

1. cd marlin/dlog
2. wasm-pack test --release --firefox
      this builds wasm module for Firefox
   wasm-pack test --release --chrome
      this builds wasm module for Chrome
3. Upon build completion and the cli prompt, open http://127.0.0.1:8000/ in Safari or Chrome browser
4. After the test execution completion, browser should display the following:

running 2 tests
test turbo_plonk::poseidon_tweedledee ... ok
test turbo_plonk::turbo_plonk ... ok
test result: ok. 2 passed; 0 failed; 0 ignored
