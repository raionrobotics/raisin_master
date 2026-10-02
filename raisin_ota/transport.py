"""Verified HTTPS, with an explicit literal-loopback development exception.

RAISIN_DEV_ALLOW_LOOPBACK_HTTP=1 affects only HTTP to 127.0.0.1 / [::1].
It never disables certificate checks. Keep this contract aligned with FMS/DP.
"""
import os
from urllib.parse import urlsplit

import requests as _requests
from requests import ConnectionError, HTTPError, RequestException, Timeout


def validate_url(url):
    try:
        if not isinstance(url, str) or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in url):
            raise ValueError
        parsed = urlsplit(url)
        port = parsed.port
        if not parsed.hostname or parsed.username is not None or parsed.password is not None or '#' in url:
            raise ValueError
        if port is not None and not 0 < port <= 65535:
            raise ValueError
        if parsed.scheme == "https":
            return "https"
        authority = parsed.netloc
        loopback = authority in ("127.0.0.1", "[::1]") or (
            authority.startswith("127.0.0.1:") and len(authority) > 10
        ) or (authority.startswith("[::1]:") and len(authority) > 6)
        if parsed.scheme == "http" and loopback and os.environ.get("RAISIN_DEV_ALLOW_LOOPBACK_HTTP") == "1":
            return "http"
    except (ValueError, TypeError):
        pass
    # Do not echo the URL, which could contain credentials or a signed query.
    raise RequestException("HTTPS required; development HTTP needs RAISIN_DEV_ALLOW_LOOPBACK_HTTP=1 and literal loopback")


class _Session(_requests.Session):
    def send(self, request, **kwargs):
        protocol = validate_url(request.url)
        if not kwargs.get("verify", self.verify):
            raise RequestException("TLS certificate verification must remain enabled")
        if protocol == "http":
            # A local credential must not reach an environment/configured proxy.
            kwargs["proxies"] = {}
        # Authentication can also live in a POST body. Never replay it or
        # accept a redirect body as an archive; configure the final URL.
        kwargs["allow_redirects"] = False
        response = super().send(request, **kwargs)
        if 300 <= response.status_code < 400:
            response.close()
            raise RequestException("OTA redirects are not supported; configure the final HTTPS or development loopback URL")
        return response


def _request(method, url, **kwargs):
    protocol = validate_url(url)  # Before Requests normalizes the authority.
    with _Session() as session:
        if protocol == "http":
            session.trust_env = False  # Neither proxy nor netrc on dev loopback.
        return session.request(method, url, **kwargs)


def get(url, **kwargs):
    return _request("GET", url, **kwargs)


def post(url, **kwargs):
    return _request("POST", url, **kwargs)
