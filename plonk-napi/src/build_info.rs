use napi_derive::napi;

#[cfg(target_os = "windows")]
#[napi]
pub const OS_NAME: &str = "Windows";

#[cfg(target_os = "linux")]
#[napi]
pub const OS_NAME: &str = "Linux";

#[cfg(target_os = "macos")]
#[napi]
pub const OS_NAME: &str = "macOS";

#[cfg(target_arch = "x86_64")]
#[napi]
pub const ARCH_NAME: &str = "x86_64";

#[cfg(target_arch = "arm")]
#[napi]
pub const ARCH_NAME: &str = "ARM";

#[cfg(target_arch = "aarch64")]
#[napi]
pub const ARCH_NAME: &str = "AArch64";
