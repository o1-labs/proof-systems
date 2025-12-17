// Compile-time check to ensure asm feature is enabled for optimal performance.
// This check can be disabled by enabling the `no-asm-check` feature.
#[cfg(all(not(feature = "asm"), not(feature = "no-asm-check")))]
compile_error!(
    "The `asm` feature is not enabled. This may result in suboptimal performance. \
     Enable the `asm` feature or set `no-asm-check` to suppress this error."
);

pub mod named;
pub mod pasta;
