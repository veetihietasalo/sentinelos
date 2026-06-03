//! Live smoke run: sweep the real machine through `MacosProvider` and print results.
//! Read-only. Run: `cargo run -p provider-macos --example sweep`
use provider_macos::MacosProvider;
use sentinel_core::provider::run_sweep;

fn main() {
    let snap = run_sweep(&MacosProvider::new());
    for r in &snap.reports {
        println!("[{:?}] {} — {} finding(s)", r.status, r.vector_id, r.findings.len());
        for f in r.findings.iter().take(5) {
            println!("    ({:?}) {} — {}", f.severity, f.title, f.detail);
        }
        if r.findings.len() > 5 {
            println!("    … +{} more", r.findings.len() - 5);
        }
    }
}
