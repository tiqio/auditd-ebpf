#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

#[cfg(target_arch = "bpf")]
mod maps;
#[cfg(target_arch = "bpf")]
mod programs;

#[cfg(not(target_arch = "bpf"))]
fn main() {
    println!("eBPF crate must be built through cargo xtask build-ebpf");
}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
