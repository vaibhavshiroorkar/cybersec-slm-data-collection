"""Screening the URLs ingestion is willing to fetch.

The catalog is filled by automated SearXNG discovery, so what lands in it is not
curated by a human before it is fetched. The screen is what stands between a
discovered URL and an internal service.

No test touches the network: DNS resolution goes through a fake resolver.
"""

import pytest

from cybersec_slm.ingestion import urlscreen


@pytest.fixture(autouse=True)
def _fake_dns(monkeypatch):
    """Resolve test hostnames without DNS. Anything unmapped is public.

    A literal IP resolves to itself, as getaddrinfo does, so the address rules are
    exercised for both spellings of the same request.
    """
    import ipaddress

    hosts = {
        "internal.test": "10.0.0.5",
        "localhost": "127.0.0.1",
        "metadata.test": "169.254.169.254",
        "evil.test": "203.0.113.7",       # public, so it passes on host grounds
        "example.test": "93.184.216.34",
        "rebind.test": "192.168.1.1",
    }

    def _resolve(host):
        try:
            return [str(ipaddress.ip_address(host))]
        except ValueError:
            return [hosts.get(host, "93.184.216.34")]

    monkeypatch.setattr(urlscreen, "_resolve", _resolve)


# ------------------------------------------------------------ what passes -----
@pytest.mark.parametrize("url", [
    "https://huggingface.co/datasets/org/x",
    "https://github.com/org/repo",
    "http://example.test/data.csv",
    "https://example.test:8443/data.csv",
])
def test_a_public_http_url_passes(url):
    assert urlscreen.screen(url) == ""


# ------------------------------------------------------------ what fails ------
@pytest.mark.parametrize("url,expect", [
    ("file:///etc/passwd", "scheme"),
    ("ftp://example.test/x", "scheme"),
    ("gopher://example.test/x", "scheme"),
    ("data:text/plain;base64,AAAA", "scheme"),
])
def test_a_non_http_scheme_is_refused(url, expect):
    assert expect in urlscreen.screen(url).lower()


def test_the_cloud_metadata_endpoint_is_refused():
    """The single most valuable SSRF target: it hands out cloud credentials."""
    reason = urlscreen.screen("http://169.254.169.254/latest/meta-data/")

    assert reason
    assert "169.254.169.254" in reason or "link-local" in reason.lower()


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8080/",
    "http://localhost/admin",
    "http://10.0.0.5/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    "http://[::1]/",
    "http://0.0.0.0/",
])
def test_a_private_or_loopback_address_is_refused(url):
    assert urlscreen.screen(url) != ""


def test_a_hostname_resolving_to_a_private_address_is_refused():
    """The check is on the resolved address, not the spelling of the host: a
    public-looking name pointed at an internal box is the whole attack."""
    assert urlscreen.screen("http://internal.test/") != ""


def test_a_hostname_resolving_to_the_metadata_address_is_refused():
    assert urlscreen.screen("http://metadata.test/latest/meta-data/") != ""


def test_credentials_in_the_url_are_refused():
    """Credentials in a fetch URL are never legitimate here and leak into logs."""
    assert "credential" in urlscreen.screen(
        "http://user:pass@example.test/x").lower()


@pytest.mark.parametrize("url", ["", "   ", "not a url", "http://", "://x"])
def test_a_malformed_url_is_refused_rather_than_passed(url):
    """Fail closed: an unparseable URL must not slip through as 'no reason to
    refuse'."""
    assert urlscreen.screen(url) != ""


def test_a_host_that_cannot_be_resolved_is_refused():
    def _boom(host):
        raise OSError("NXDOMAIN")

    import cybersec_slm.ingestion.urlscreen as m
    orig = m._resolve
    m._resolve = _boom
    try:
        assert m.screen("http://nowhere.test/") != ""
    finally:
        m._resolve = orig


def test_screening_is_reported_as_a_reason_not_a_bool():
    """The caller logs it, so it has to say what was wrong."""
    reason = urlscreen.screen("http://10.0.0.5/")

    assert isinstance(reason, str) and len(reason) > 10


# ------------------------------------------------------------ redirects -------
def test_check_raises_for_a_refused_url():
    with pytest.raises(urlscreen.BlockedURL) as e:
        urlscreen.check("http://169.254.169.254/")

    assert "169.254.169.254" in str(e.value)


def test_check_is_silent_for_an_allowed_url():
    assert urlscreen.check("https://example.test/x") is None


# ------------------------------------- the choke point: http_get and download --
class _Resp:
    """An httpx-shaped response, redirecting when `location` is set."""

    def __init__(self, url, location=None, body=b"data"):
        self.url = url
        self.status_code = 302 if location else 200
        self.headers = {"location": location} if location else {}
        self.is_redirect = bool(location)
        self.content = body
        self._body = body

    def raise_for_status(self):
        return None

    def iter_bytes(self, n=None):
        yield self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_http_get_refuses_a_blocked_url(monkeypatch):
    from cybersec_slm.ingestion import common

    monkeypatch.setattr(urlscreen, "_resolve", lambda h: ["169.254.169.254"])
    with pytest.raises(urlscreen.BlockedURL):
        common.http_get("http://metadata.test/latest/meta-data/")


def test_download_refuses_a_blocked_url(tmp_path, monkeypatch):
    from cybersec_slm.ingestion import common

    monkeypatch.setattr(urlscreen, "_resolve", lambda h: ["10.0.0.5"])
    with pytest.raises(urlscreen.BlockedURL):
        common.download("http://internal.test/x.csv", str(tmp_path / "x.csv"))


def test_a_redirect_into_a_private_address_is_refused(monkeypatch):
    """The case a naive screen misses. Screening only the URL the caller passed is
    no defence: a public URL that 302s to 169.254.169.254 reaches the metadata
    endpoint anyway, and httpx would follow it silently."""
    from cybersec_slm.ingestion import common

    addrs = {"public.test": "93.184.216.34", "metadata.test": "169.254.169.254"}
    monkeypatch.setattr(urlscreen, "_resolve", lambda h: [addrs.get(h, "93.184.216.34")])

    def _get(url, **kw):
        if "public.test" in url:
            return _Resp(url, location="http://metadata.test/latest/meta-data/")
        raise AssertionError(f"followed the redirect to {url}")

    monkeypatch.setattr(common.httpx, "get", _get)

    with pytest.raises(urlscreen.BlockedURL):
        common.http_get("http://public.test/data")


def test_an_ordinary_redirect_is_still_followed(monkeypatch):
    """The screen must not break the redirects real sources rely on."""
    from cybersec_slm.ingestion import common

    monkeypatch.setattr(urlscreen, "_resolve", lambda h: ["93.184.216.34"])
    seen = []

    def _get(url, **kw):
        seen.append(url)
        if url.endswith("/start"):
            return _Resp(url, location="https://example.test/final")
        return _Resp(url, body=b"landed")

    monkeypatch.setattr(common.httpx, "get", _get)

    r = common.http_get("https://example.test/start")

    assert r.content == b"landed"
    assert seen == ["https://example.test/start", "https://example.test/final"]


def test_a_redirect_loop_gives_up_rather_than_spinning(monkeypatch):
    from cybersec_slm.ingestion import common

    monkeypatch.setattr(urlscreen, "_resolve", lambda h: ["93.184.216.34"])
    monkeypatch.setattr(common.httpx, "get",
                        lambda url, **kw: _Resp(url, location="https://example.test/a"))

    with pytest.raises(Exception, match="redirect"):
        common.http_get("https://example.test/a")
