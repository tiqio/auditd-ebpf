use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "auditd-ebpf", version, about = "Rust/Aya Linux 审计服务")]
struct Cli {
    /// 输出构建骨架信息后退出。
    #[arg(long)]
    build_info: bool,
}

fn main() {
    let cli = Cli::parse();
    if cli.build_info {
        println!(
            "auditd-ebpf schema={} rules_max={}",
            auditd_ebpf_common::schema_version(),
            auditd_ebpf_rules::max_rules()
        );
    }
}
