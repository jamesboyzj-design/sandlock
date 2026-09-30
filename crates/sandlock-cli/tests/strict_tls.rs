use std::path::Path;
use std::process::Command;

#[test]
fn strict_python_tls_uses_generated_ca_and_leaf() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/strict_tls.py");
    let out = Command::new("python3")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_sandlock"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
