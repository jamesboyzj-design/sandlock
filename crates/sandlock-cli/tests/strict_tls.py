"""Linux integration probe: openssl + Python stdlib, strict verification enabled."""
import http.server
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading


def openssl(*args):
    subprocess.run(['openssl', *args], check=True, capture_output=True, timeout=15)


def main(binary):
    with tempfile.TemporaryDirectory(prefix='sandlock-strict-tls-') as directory:
        root = Path(directory)
        ca, key, leaf, leafkey, csr = (root / n for n in ('ca.pem', 'ca.key', 'leaf.pem', 'leaf.key', 'leaf.csr'))
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
                '-out', str(ca), '-days', '1', '-subj', '/CN=Test upstream CA')
        openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(leafkey),
                '-out', str(csr), '-subj', '/CN=localhost')
        ext = root / 'leaf.ext'
        ext.write_text('subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n'
                       'extendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid,issuer\n')
        openssl('x509', '-req', '-in', str(csr), '-CA', str(ca), '-CAkey', str(key),
                '-CAcreateserial', '-out', str(leaf), '-days', '1', '-extfile', str(ext))
        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.headers.get('Authorization') == 'Bearer synthetic-tls-probe')
                self.send_response(200)
                self.send_header('Content-Length', '2')
                self.end_headers()
                self.wfile.write(b'ok')

            def log_message(*args):
                pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(leaf, leafkey)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            args = [binary, 'run', '--timeout', '10', '--clean-env']
            for path in ('/usr', '/bin', '/lib', '/lib64', '/etc'):
                if Path(path).exists():
                    args += ['-r', path]
            args += ['--http-allow', 'GET localhost/check', '--http-port', str(server.server_port),
                     '--http-inject-ca', '/etc/ssl/certs/ca-certificates.crt',
                     '--credential', 'test=env:SL_TEST_CREDENTIAL',
                     '--http-auth', 'GET localhost/check bearer test', '--', 'python3', '-c',
                     'import os,ssl,urllib.request;'
                     'assert "SL_TEST_CREDENTIAL" not in os.environ;'
                     'ctx=ssl.create_default_context(cafile="/etc/ssl/certs/ca-certificates.crt");'
                     'ctx.verify_flags |= ssl.VERIFY_X509_STRICT;'
                     f'assert urllib.request.urlopen("https://localhost:{server.server_port}/check",'
                     'context=ctx,timeout=5).read()==b"ok"']
            env = {'PATH': '/usr/bin:/bin', 'HOME': str(Path.home()), 'SSL_CERT_FILE': str(ca),
                   'SL_TEST_CREDENTIAL': 'synthetic-tls-probe'}
            result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=20)
            assert result.returncode == 0, result.stderr
            assert received == [True], received
            print('PASS: strict TLS verified; synthetic credential received by real HTTPS server')
        finally:
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    main(sys.argv[1])
