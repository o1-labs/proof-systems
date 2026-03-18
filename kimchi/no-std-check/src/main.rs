#![no_std]
#![no_main]

extern crate kimchi;

#[no_mangle]
fn main() {}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
