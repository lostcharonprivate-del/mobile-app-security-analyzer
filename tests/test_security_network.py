"""Security tests for the tool's own network behaviour.

The promise made in the README and in the UI is specific: analysis is local, and
the only thing that may ever leave the machine is a library coordinate the user
opted into looking up. These tests hold the code to that promise by intercepting
the transport rather than trusting the call sites.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import pytest

from conftest import make_apk_like
from masa.config import ScanConfig
from masa.osv import Coordinate, OsvClient
from masa.runner import scan


class _Interceptor:
    """Stands in for urlopen and records everything that would be sent."""

    def __init__(self, response: dict | None = None) -> None:
        self.requests: list[urllib.request.Request] = []
        self.response = response if response is not None else {"vulns": []}

    def __call__(self, request, timeout=None):  # noqa: ANN001
        self.requests.append(request)
        payload = json.dumps(self.response).encode()

        class _Response:
            def read(self_inner, _size=None):
                return payload

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *args):
                return False

        return _Response()

    @property
    def bodies(self) -> list[dict]:
        return [json.loads(r.data.decode()) for r in self.requests if r.data]


@pytest.fixture
def intercept(monkeypatch):
    interceptor = _Interceptor()
    monkeypatch.setattr(urllib.request, "urlopen", interceptor)
    return interceptor


class TestOfflineByDefault:
    def test_scan_makes_no_request_by_default(self, intercept, apk_path: Path):
        scan(apk_path, ScanConfig())
        assert intercept.requests == [], "a default scan reached the network"

    def test_config_defaults_to_offline(self):
        config = ScanConfig()
        assert config.enable_network is False
        assert config.offline_only is True

    def test_osv_client_is_offline_by_default(self, intercept, tmp_path: Path):
        client = OsvClient(cache_path=tmp_path / "cache.json")
        client.query_batch([Coordinate("Maven", "group:artifact", "1.0.0")])
        assert intercept.requests == []
        assert any("disabled" in error for error in client.errors)

    def test_offline_scan_still_reports_the_inventory(self, intercept, tmp_path: Path):
        archive = make_apk_like(
            tmp_path / "libs.apk",
            {"META-INF/androidx.core_core.version": b"1.9.0\n"},
        )
        report = scan(archive, ScanConfig()).report
        assert intercept.requests == []
        inventory = [f for f in report.findings if f.rule_id == "DEP-INVENTORY"]
        assert inventory, "no inventory finding was produced offline"
        assert "network access is disabled" in inventory[0].description


class TestOnlineRequestsCarryOnlyCoordinates:
    def test_only_name_and_version_are_transmitted(self, intercept, tmp_path: Path):
        client = OsvClient(enabled=True, cache_path=tmp_path / "cache.json")
        client.query_batch([Coordinate("Maven", "com.example:lib", "1.2.3")])
        assert len(intercept.bodies) == 1
        body = intercept.bodies[0]
        assert body == {
            "package": {"name": "com.example:lib", "ecosystem": "Maven"},
            "version": "1.2.3",
        }

    def test_no_package_content_reaches_the_request(self, intercept, tmp_path: Path):
        """The decisive test: scan a package full of markers, check the wire."""
        marker = "UNIQUE-CANARY-STRING-4f3a91"
        archive = make_apk_like(
            tmp_path / "canary.apk",
            {
                "META-INF/androidx.core_core.version": b"1.9.0\n",
                "assets/secrets.txt": f"api_key={marker}\n".encode(),
                f"assets/{marker}.txt": marker.encode(),
            },
        )
        scan(archive, ScanConfig().with_network(True))

        transmitted = json.dumps(intercept.bodies) + "".join(
            request.full_url for request in intercept.requests
        )
        assert marker not in transmitted, "package content was transmitted"
        assert "canary.apk" not in transmitted, "the file name was transmitted"
        # No hash of the analysed file may be sent either.
        report = scan(archive, ScanConfig()).report
        assert report.app.sha256 not in transmitted

    def test_requests_go_only_to_osv(self, intercept, tmp_path: Path):
        client = OsvClient(enabled=True, cache_path=tmp_path / "cache.json")
        client.query_batch([Coordinate("Maven", "a:b", "1.0")])
        for request in intercept.requests:
            assert request.full_url.startswith("https://api.osv.dev/")

    def test_user_agent_does_not_identify_the_analysed_app(
        self, intercept, tmp_path: Path
    ):
        client = OsvClient(enabled=True, cache_path=tmp_path / "cache.json")
        client.query_batch([Coordinate("Maven", "a:b", "1.0")])
        agent = intercept.requests[0].get_header("User-agent")
        assert "mobile-app-security-analyzer" in agent
        assert "a:b" not in agent


class TestNetworkFailureHandling:
    def test_a_network_error_does_not_fail_the_scan(self, monkeypatch, tmp_path: Path):
        def _boom(request, timeout=None):  # noqa: ANN001
            raise OSError("network is unreachable")

        monkeypatch.setattr(urllib.request, "urlopen", _boom)
        archive = make_apk_like(
            tmp_path / "libs.apk", {"META-INF/androidx.core_core.version": b"1.9.0\n"}
        )
        report = scan(archive, ScanConfig().with_network(True)).report
        assert report.findings  # the rest of the analysis still ran
        assert not report.errors or all("analyzer" not in e for e in report.errors)

    def test_malformed_response_is_handled(self, monkeypatch, tmp_path: Path):
        class _Garbage:
            def read(self, _size=None):
                return b"not json at all"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Garbage())
        client = OsvClient(enabled=True, cache_path=tmp_path / "cache.json")
        result = client.query_batch([Coordinate("Maven", "a:b", "1.0")])
        assert result == {} or result.get("Maven|a:b|1.0") == []
        assert client.errors

    def test_oversized_response_is_capped(self, monkeypatch, tmp_path: Path):
        recorded: dict[str, int] = {}

        class _Huge:
            def read(self, size=None):
                recorded["size"] = size or -1
                return json.dumps({"vulns": []}).encode()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Huge())
        OsvClient(enabled=True, cache_path=tmp_path / "cache.json").query_batch(
            [Coordinate("Maven", "a:b", "1.0")]
        )
        assert 0 < recorded["size"] <= 8 * 1024 * 1024


class TestCache:
    def test_results_are_cached_and_reused_offline(self, tmp_path: Path, monkeypatch):
        cache = tmp_path / "cache.json"
        interceptor = _Interceptor({"vulns": [{"id": "GHSA-test", "summary": "x"}]})
        monkeypatch.setattr(urllib.request, "urlopen", interceptor)

        coordinate = Coordinate("Maven", "a:b", "1.0")
        first = OsvClient(enabled=True, cache_path=cache)
        assert len(first.query_batch([coordinate])[coordinate.key]) == 1
        assert len(interceptor.requests) == 1

        second = OsvClient(enabled=False, cache_path=cache)
        cached = second.query_batch([coordinate])
        assert len(cached[coordinate.key]) == 1
        assert len(interceptor.requests) == 1, "the cache was not used"

    def test_a_corrupt_cache_is_ignored(self, tmp_path: Path):
        cache = tmp_path / "cache.json"
        cache.write_text("{not json")
        client = OsvClient(enabled=False, cache_path=cache)
        assert client.query_batch([Coordinate("Maven", "a:b", "1.0")]) == {}
