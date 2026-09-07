"""OSV.dev vulnerability lookup with a local cache.

Network access is off by default and must be enabled explicitly. When it is on,
the only thing that leaves the machine is a package coordinate and version string
— never a file, a hash of the analysed app, a path, or anything else derived from
the package's contents. That constraint is what `query_batch` enforces.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

_OSV_URL = "https://api.osv.dev/v1/query"
_USER_AGENT = "mobile-app-security-analyzer (static analysis; no app data transmitted)"
_TIMEOUT = 20
_MAX_LOOKUPS = 60
_MAX_VULNS_PER_LIBRARY = 20
_CACHE_TTL = 24 * 60 * 60


@dataclass(frozen=True)
class Coordinate:
    """A library identity. This, and only this, is what is sent to OSV."""

    ecosystem: str
    name: str
    version: str

    @property
    def key(self) -> str:
        return f"{self.ecosystem}|{self.name}|{self.version}"


@dataclass
class Vulnerability:
    id: str
    summary: str = ""
    severity: str = ""
    aliases: list[str] = field(default_factory=list)

    @property
    def url(self) -> str:
        return f"https://osv.dev/vulnerability/{self.id}"

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "summary": self.summary,
            "severity": self.severity,
            "aliases": list(self.aliases),
            "url": self.url,
        }


def default_cache_path() -> Path:
    return Path.home() / ".cache" / "mobile-app-security-analyzer" / "osv.json"


class OsvClient:
    """Batched OSV.dev client. Offline by default; cache is always consulted."""

    def __init__(
        self,
        enabled: bool = False,
        cache_path: Path | None = None,
        ttl: int = _CACHE_TTL,
    ) -> None:
        self.enabled = enabled
        self.cache_path = cache_path or default_cache_path()
        self.ttl = ttl
        self.errors: list[str] = []
        self._cache = self._load_cache()

    def _load_cache(self) -> dict[str, dict]:
        try:
            raw = json.loads(self.cache_path.read_text("utf-8"))
        except (OSError, ValueError):
            return {}
        if not isinstance(raw, dict):
            return {}
        now = time.time()
        return {
            key: entry
            for key, entry in raw.items()
            if isinstance(entry, dict) and now - entry.get("fetched_at", 0) < self.ttl
        }

    def save_cache(self) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self._cache), "utf-8")
        except OSError as exc:
            self.errors.append(f"could not write OSV cache: {exc}")

    def query_batch(
        self, coordinates: Iterable[Coordinate]
    ) -> dict[str, list[Vulnerability]]:
        """Look up each coordinate. Returns coordinate.key -> vulnerabilities."""
        wanted = list(dict.fromkeys(coordinates))
        results: dict[str, list[Vulnerability]] = {}
        missing: list[Coordinate] = []

        for coordinate in wanted:
            cached = self._cache.get(coordinate.key)
            if cached is not None:
                results[coordinate.key] = [
                    Vulnerability(**item) for item in cached.get("vulns", [])
                ]
            else:
                missing.append(coordinate)

        if not missing:
            return results
        if not self.enabled:
            self.errors.append(
                f"{len(missing)} librarie(s) were not checked against OSV: network "
                "lookups are disabled (pass --online to enable)"
            )
            return results

        if len(missing) > _MAX_LOOKUPS:
            self.errors.append(
                f"{len(missing)} libraries need a lookup; querying the first "
                f"{_MAX_LOOKUPS}"
            )
            missing = missing[:_MAX_LOOKUPS]

        for coordinate in missing:
            vulns = self._fetch(coordinate)
            if vulns is None:
                break  # network is failing; stop rather than retry per library
            results[coordinate.key] = vulns
            self._cache[coordinate.key] = {
                "fetched_at": time.time(),
                "vulns": [_strip(v) for v in vulns],
            }
        self.save_cache()
        return results

    def _fetch(self, coordinate: Coordinate) -> list[Vulnerability] | None:
        """Query one coordinate. Returns None when the network itself failed.

        The request body is built solely from the coordinate. Nothing derived
        from the analysed package's contents can reach this payload.
        """
        payload = {
            "package": {"name": coordinate.name, "ecosystem": coordinate.ecosystem},
            "version": coordinate.version,
        }
        request = urllib.request.Request(
            _OSV_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": _USER_AGENT},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
                body = json.loads(response.read(8 * 1024 * 1024).decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            self.errors.append(f"OSV lookup failed for {coordinate.name}: {exc}")
            return None

        items = body.get("vulns", []) if isinstance(body, dict) else []
        vulns = [
            _to_vulnerability(item) for item in items if isinstance(item, dict)
        ]
        # Newest identifiers first, so the sample shown in the report is the most
        # recently published rather than whatever the API happened to order first.
        vulns.sort(key=lambda v: v.id, reverse=True)
        return vulns[:_MAX_VULNS_PER_LIBRARY]


def _strip(vulnerability: Vulnerability) -> dict[str, object]:
    return {
        "id": vulnerability.id,
        "summary": vulnerability.summary,
        "severity": vulnerability.severity,
        "aliases": list(vulnerability.aliases),
    }


def _to_vulnerability(item: dict) -> Vulnerability:
    severity = ""
    for entry in item.get("severity", []) or []:
        if isinstance(entry, dict) and entry.get("score"):
            severity = str(entry["score"])
            break
    database = item.get("database_specific") or {}
    if not severity and isinstance(database, dict):
        severity = str(database.get("severity", ""))
    return Vulnerability(
        id=str(item.get("id", "")),
        summary=str(item.get("summary", ""))[:400],
        severity=severity,
        aliases=[str(a) for a in (item.get("aliases") or [])][:10],
    )
