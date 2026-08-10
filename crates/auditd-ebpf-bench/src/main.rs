use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "auditd-ebpf-bench", version, about = "auditd 对照基准驱动")]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
    println!("benchmark harness skeleton");
}
