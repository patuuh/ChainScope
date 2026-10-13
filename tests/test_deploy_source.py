import io
import urllib.error

import pytest
from core import deploy_source


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("1", 1),
        ("eth", 1),
        ("mainnet", 1),
        ("etherscan.io", 1),
        ("8453", 8453),
        ("base", 8453),
        ("basescan.org", 8453),
        ("42161", 42161),
        ("arbitrum", 42161),
        ("arb", 42161),
        ("arbiscan.io", 42161),
        ("999", 999),
        ("hyperevm", 999),
        ("hyperevmscan.io", 999),
        ("https://arbiscan.io", 42161),
    ],
)
def test_chain_id_normalization(raw, expected):
    assert deploy_source.chain_id(raw) == expected


def test_chain_id_unknown_raises():
    with pytest.raises(ValueError):
        deploy_source.chain_id("not-a-chain")


class _FakeHTTPError(urllib.error.HTTPError):
    """HTTPError carrying a JSON body, as Sourcify returns for unverified contracts."""

    def __init__(self, code, body):
        super().__init__("https://sourcify.dev", code, "Not Found", {}, io.BytesIO(body))
        self._body = body

    def read(self, *a):
        return self._body


def test_sourcify_get_returns_json_body_on_404(monkeypatch):
    """Sourcify signals 'no match' with HTTP 404 + JSON; the body must survive."""

    def boom(req, timeout=None):
        raise _FakeHTTPError(404, b'{"match":null,"chainId":"388"}')

    monkeypatch.setattr(deploy_source.urllib.request, "urlopen", boom)
    status, payload = deploy_source._sourcify_get("https://sourcify.dev/x", 10)
    assert status == 404
    assert payload["match"] is None


def test_sourcify_get_non_json_body_raises_unreachable(monkeypatch):
    def boom(req, timeout=None):
        raise _FakeHTTPError(429, b"<html>rate limited</html>")

    monkeypatch.setattr(deploy_source.urllib.request, "urlopen", boom)
    with pytest.raises(deploy_source.UnreachableError):
        deploy_source._sourcify_get("https://sourcify.dev/x", 10)


def test_sourcify_get_url_error_raises_unreachable(monkeypatch):
    def boom(req, timeout=None):
        raise urllib.error.URLError("dns failure")

    monkeypatch.setattr(deploy_source.urllib.request, "urlopen", boom)
    with pytest.raises(deploy_source.UnreachableError):
        deploy_source._sourcify_get("https://sourcify.dev/x", 10)


def test_fetch_sourcify_source_unverified_raises_not_verified(monkeypatch):
    """A 404+match=null must raise NotVerifiedError, not a bare HTTPError."""
    monkeypatch.setattr(
        deploy_source,
        "_sourcify_get",
        lambda url, timeout: (404, {"match": None, "chainId": "388"}),
    )
    with pytest.raises(deploy_source.NotVerifiedError):
        deploy_source.fetch_sourcify_source(388, "0x" + "ab" * 20, "/tmp/x")


def test_fetch_many_tags_error_kind(monkeypatch):
    def fake(*a, **kw):
        raise deploy_source.NotVerifiedError("nope")

    monkeypatch.setattr(deploy_source, "fetch_sourcify_source", fake)
    res = deploy_source.fetch_many(["388:0x" + "ab" * 20], "/tmp/x")
    assert res[0]["error_kind"] == "not_verified"


def test_coverage_separates_verified_from_unverified(monkeypatch):
    """coverage() must hit the bare v2 endpoint; ?fields=match is rejected by Sourcify."""
    seen = []

    def fake_get(url, timeout):
        seen.append(url)
        if "388" in url:
            return 404, {"match": None}
        return 200, {"match": "match"}

    monkeypatch.setattr(deploy_source, "_sourcify_get", fake_get)
    cov = deploy_source.coverage(["1:0x" + "aa" * 20, "388:0x" + "bb" * 20])
    assert cov["coverage"] == 0.5
    assert len(cov["unverified"]) == 1
    assert all("fields=" not in u for u in seen)
