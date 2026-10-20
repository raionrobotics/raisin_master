"""Exercise the real socket boundary; all credentials are fixture-only."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import ssl
import subprocess
import threading
from unittest.mock import patch

import pytest
from raisin_ota import transport


@contextmanager
def peer(redirect=None, tls=None):
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            seen.append(dict(self.headers))
            self.send_response(302 if redirect else 200)
            if redirect: self.send_header('Location', redirect)
            self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'{}')
        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length', 0)))
            self.do_GET()
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*tls)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}); thread.start()
    try: yield f'{"https" if tls else "http"}://127.0.0.1:{server.server_port}', seen
    finally: server.shutdown(); server.server_close(); thread.join(3)


@pytest.mark.parametrize('flag', ['', '0', 'true'])
def test_http_is_not_implicitly_enabled(flag):
    with peer() as (url, seen), patch.dict(os.environ, RAISIN_DEV_ALLOW_LOOPBACK_HTTP=flag):
        with pytest.raises(transport.RequestException): transport.get(url, timeout=1)
        assert seen == []


def test_explicit_loopback_ignores_environment_proxy_and_delivers_test_key():
    with peer() as (proxy, intercepted), peer() as (url, seen), patch.dict(os.environ,
            RAISIN_DEV_ALLOW_LOOPBACK_HTTP='1', HTTP_PROXY=proxy, http_proxy=proxy, NO_PROXY='', no_proxy=''):
        reply = transport.get(url, headers={'X-Robot-Api-Key': 'rk_fixture_only'}, timeout=2)
        assert reply.status_code == 200 and len(seen) == 1 and intercepted == []
        assert transport.get(url.replace('http:', 'HtTp:', 1), timeout=2).status_code == 200
        assert len(seen) == 2 and intercepted == []


@pytest.mark.parametrize('url', ['http://192.168.10.100', 'http://example.com', 'http://localhost',
    'http://127.1', 'http://2130706433', 'http://0x7f000001', 'http://127.0.0.1.evil',
    'http://127.0.0.1:80@evil', 'http://user@127.0.0.1', 'http://127.0.0.1:65536',
    'http://127.0.0.1\\@evil', 'http://[::ffff:127.0.0.1]', 'http://127.0.0.1/#secret'])
def test_opt_in_does_not_allow_lan_dns_or_ambiguous_addresses(url):
    with patch.dict(os.environ, RAISIN_DEV_ALLOW_LOOPBACK_HTTP='1'):
        with pytest.raises(transport.RequestException): transport.validate_url(url)


def test_ipv6_literal_is_allowed_only_with_opt_in():
    with patch.dict(os.environ, RAISIN_DEV_ALLOW_LOOPBACK_HTTP='1'):
        assert transport.validate_url('http://[::1]:8001/api') == 'http'


def test_credential_redirect_is_not_followed_even_to_another_local_peer():
    with peer() as (target, seen), peer(target) as (url, first), patch.dict(os.environ, RAISIN_DEV_ALLOW_LOOPBACK_HTTP='1'):
        with pytest.raises(transport.RequestException, match='redirects'):
            transport.get(url, headers={'X-Robot-Api-Key':'rk_fixture_only'}, timeout=2)
        assert len(first) == 1 and seen == []


def test_post_credentials_and_anonymous_downloads_do_not_follow_redirects():
    with peer() as (target, seen), peer(target) as (url, first), patch.dict(os.environ, RAISIN_DEV_ALLOW_LOOPBACK_HTTP='1'):
        with pytest.raises(transport.RequestException, match='redirects'):
            transport.post(url, json={'signature':'fixture-only'}, timeout=2)
        with pytest.raises(transport.RequestException, match='redirects'):
            transport.get(url, stream=True, timeout=2)
        assert len(first) == 2 and seen == []


def test_https_still_requires_a_trusted_ca_with_development_flag(tmp_path):
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-keyout', str(key), '-out', str(cert), '-subj', '/CN=fixture',
                    '-addext', 'subjectAltName=IP:127.0.0.1'], check=True, capture_output=True)
    with peer(tls=(cert,key)) as (url,seen), patch.dict(os.environ, RAISIN_DEV_ALLOW_LOOPBACK_HTTP='1'):
        with pytest.raises(transport.RequestException): transport.get(url, timeout=2)
        assert seen == []
        request = transport._requests.Request('GET',url).prepare()
        with transport._Session() as session:
            session.verify = False
            with pytest.raises(transport.RequestException, match='verification'): session.send(request,timeout=2)
            session.verify = True
            # Explicit None reaches the adapter unchanged in Session.send;
            # falling back to session.verify here would accidentally allow it.
            with pytest.raises(transport.RequestException, match='verification'): session.send(request,verify=None,timeout=2)
        assert seen == []
        assert transport.get(url.replace('https:','HTTPS:',1), verify=str(cert), timeout=2).status_code == 200


@pytest.mark.parametrize('verify', [False, '', 0])
def test_development_flag_cannot_disable_tls_verification(verify):
    with patch.dict(os.environ, RAISIN_DEV_ALLOW_LOOPBACK_HTTP='1'):
        with pytest.raises(transport.RequestException, match='verification'):
            transport.get('https://127.0.0.1:1', verify=verify, timeout=1)
