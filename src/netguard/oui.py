"""MAC vendor lookup, using Wireshark's `manuf` list of IEEE OUI assignments.

The list is an optional download (a few MB). Without it NetGuard still works,
it just shows no vendor names. The download resumes where it stopped, so it
survives a slow or flaky connection.
"""

from __future__ import annotations

import http.client
import shutil
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

from netguard import __version__

MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"


class DownloadError(RuntimeError):
    pass


class VendorDB:
    """Longest-prefix lookup of MAC address -> vendor name.

    The IEEE hands out blocks of 24 bits (most vendors), 28 bits or 36 bits,
    so a MAC is checked against the longest prefixes first.
    """

    def __init__(self, prefixes: dict[int, dict[int, str]] | None = None):
        self._prefixes = prefixes or {}  # prefix length in bits -> {prefix: vendor}
        self._lengths = sorted(self._prefixes, reverse=True)

    def __len__(self) -> int:
        return sum(len(table) for table in self._prefixes.values())

    @classmethod
    def from_text(cls, text: str) -> VendorDB:
        prefixes: dict[int, dict[int, str]] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # "00:1B:C5:00:00:00/36<TAB>Convergi<TAB>Converging Systems Inc."
            # The real file pads columns with spaces before the tab.
            fields = [f.strip() for f in line.split("\t")]
            if len(fields) < 2:
                continue
            prefix, _, bits_text = fields[0].partition("/")
            digits = prefix.replace(":", "").replace("-", "")
            try:
                value = int(digits, 16)
                bits = int(bits_text) if bits_text else len(digits) * 4
            except ValueError:
                continue
            if not 0 < bits <= min(len(digits) * 4, 48):
                continue
            name = fields[2] if len(fields) > 2 and fields[2] else fields[1]
            prefixes.setdefault(bits, {})[value >> (len(digits) * 4 - bits)] = name
        return cls(prefixes)

    @classmethod
    def load(cls, path: Path) -> VendorDB:
        """Load the list, or return an empty database if it was never downloaded."""
        if not path.exists():
            return cls()
        return cls.from_text(path.read_text(encoding="utf-8", errors="replace"))

    def lookup(self, mac: str) -> str | None:
        value = int(mac.replace(":", ""), 16)
        for bits in self._lengths:
            vendor = self._prefixes[bits].get(value >> (48 - bits))
            if vendor:
                return vendor
        return None


def download(
    url: str,
    dest: Path,
    retries: int = 5,
    timeout: float = 30,
    sleep: Callable[[float], None] = time.sleep,
) -> Path:
    """Download `url` to `dest`, resuming a partial `.part` file after errors."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")

    for attempt in range(1, retries + 1):
        have = part.stat().st_size if part.exists() else 0
        headers = {"User-Agent": f"netguard/{__version__}"}
        if have:
            headers["Range"] = f"bytes={have}-"
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, headers=headers), timeout=timeout
            ) as resp:
                # A server that ignores Range sends the whole file (200): start over.
                mode = "ab" if have and resp.status == 206 else "wb"
                with open(part, mode) as fh:
                    shutil.copyfileobj(resp, fh, 64 * 1024)
            break
        except urllib.error.HTTPError as exc:
            if exc.code == 416 and have:  # nothing left to fetch: the .part is complete
                break
            if exc.code < 500 or attempt == retries:
                raise DownloadError(f"download failed: HTTP {exc.code} from {url}") from exc
        except (OSError, http.client.HTTPException) as exc:
            if attempt == retries:
                raise DownloadError(f"download failed after {retries} attempts: {exc}") from exc
        sleep(min(2**attempt, 30))

    if not len(VendorDB.load(part)):
        part.unlink()
        raise DownloadError(f"{url} did not return a vendor list")
    part.replace(dest)
    return dest
