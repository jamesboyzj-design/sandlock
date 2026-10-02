use sandlock_core::Sandbox;
use std::time::Duration;

/// Strict verification must complete before the proxy denies the HTTP path.
/// localhost resolves without public DNS and passes the proxy's Host/IP check;
/// no upstream listener is needed because the ACL rejects before forwarding.
#[tokio::test]
async fn strict_x509_reaches_http_acl_denial() {
    let dir = tempfile::tempdir().expect("temporary trust bundle directory");
    let bundle = dir.path().join("bundle.pem");
    std::fs::write(&bundle, b"").expect("create empty trust bundle");
    let path = std::env::var_os("PATH").expect("PATH to locate python3");
    let python_dir = std::env::split_paths(&path)
        .find(|dir| dir.join("python3").is_file())
        .expect("python3 installed on PATH");

    let mut sandbox = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read(&python_dir)
        .fs_read(dir.path())
        .clean_env(true)
        .env_var("PATH", python_dir.to_str().expect("UTF-8 Python directory"))
        .http_allow("GET localhost/allowed")
        .http_inject_ca(&bundle)
        .build()
        .expect("strict TLS sandbox policy");

    let script = r#"
import ssl
import sys
import urllib.error
import urllib.request

context = ssl.create_default_context(cafile=sys.argv[1])
context.verify_flags |= ssl.VERIFY_X509_STRICT
assert context.verify_mode == ssl.CERT_REQUIRED
assert context.check_hostname
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=context),
)
try:
    with opener.open('https://localhost/denied', timeout=10) as response:
        raise AssertionError(f'expected ACL denial, got {response.status}')
except urllib.error.HTTPError as error:
    with error:
        assert error.code == 403, f'expected 403, got {error.code}'
        body = error.read()
        assert body == b'Blocked by sandlock HTTP ACL policy', repr(body)
    print('strict X509 verified; HTTP 403: Blocked by sandlock HTTP ACL policy')
"#;
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        sandbox.run(&["python3", "-c", script, bundle.to_str().unwrap()]),
    )
    .await
    .expect("strict TLS sandbox must finish within 30 seconds")
    .expect("run strict TLS sandbox");
    assert!(
        result.success(),
        "strict TLS client status={:?}\nstdout={}\nstderr={}",
        result.code(),
        String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default()),
        String::from_utf8_lossy(result.stderr.as_deref().unwrap_or_default()),
    );
    assert_eq!(
        std::fs::read(&bundle).unwrap(),
        b"",
        "host bundle unchanged"
    );
}
