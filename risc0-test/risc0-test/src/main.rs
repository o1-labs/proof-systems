use risc0_zkvm::guest::env;

fn main() {
    env::commit(&"hello from risc0 guest");
}
