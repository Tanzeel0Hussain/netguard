"""TCP connect scan with banner grabbing, using asyncio. Needs no root.

A connect scan completes the TCP handshake, exactly like a normal client, so
it is the politest kind of scan: no crafted packets, nothing half-open. To be
a good citizen on the network it also limits how many connections are open at
once and how long each one may take.
"""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Iterable
from dataclasses import dataclass

# Common TCP ports on home networks: remote access, file sharing, web admin
# pages, IoT and cameras, printers, and databases left open by mistake.
COMMON_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 554, 631, 1883, 2323,
    3306, 3389, 5000, 5432, 5900, 6379, 7547, 8000, 8080, 8443, 8888, 9100,
    9200, 27017, 49152,
)
HTTP_PORTS = {80, 5000, 8000, 8080, 8888, 49152}
TLS_PORTS = {443, 8443}
BANNER_BYTES = 512


@dataclass(frozen=True)
class OpenPort:
    ip: str
    port: int
    banner: str = ""  # first line(s) the service sent, or the HTTP Server header
    tls: bool = False


async def _read_banner(reader: asyncio.StreamReader, timeout: float) -> str:
    try:
        data = await asyncio.wait_for(reader.read(BANNER_BYTES), timeout)
    except (TimeoutError, OSError):
        return ""
    return data.decode("latin-1", errors="replace").strip()


def _http_server_header(response: str) -> str:
    for line in response.splitlines()[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "server":
            return value.strip()
    first = response.splitlines()[0] if response else ""
    return first if first.startswith("HTTP/") else ""


async def probe(
    ip: str, port: int, timeout: float = 1.0, http: bool | None = None
) -> OpenPort | None:
    """Connect to one port. Returns None if it is closed or filtered.

    `http` says whether to send a HEAD request; by default it depends on the port.
    """
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except (TimeoutError, OSError):
        return None

    use_http = port in HTTP_PORTS if http is None else http
    try:
        if use_http:
            # The only thing we ever send: a HEAD request for the front page.
            writer.write(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            await writer.drain()
            return OpenPort(ip, port, _http_server_header(await _read_banner(reader, timeout)))
        banner = await _read_banner(reader, timeout)  # SSH, FTP, SMTP... speak first
        return OpenPort(ip, port, banner.splitlines()[0][:200] if banner else "")
    except OSError:
        return OpenPort(ip, port)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def probe_tls(ip: str, port: int, timeout: float = 1.0) -> bool:
    """True if the port completes a TLS handshake (certificates are not checked)."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=context), timeout
        )
    except (TimeoutError, OSError, ssl.SSLError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except (OSError, ssl.SSLError):
        pass
    return True


async def scan_hosts(
    ips: Iterable[str],
    ports: Iterable[int] = COMMON_PORTS,
    timeout: float = 1.0,
    concurrency: int = 100,
) -> list[OpenPort]:
    """Probe every port on every host, at most `concurrency` connections at a time."""
    limit = asyncio.Semaphore(concurrency)

    async def one(ip: str, port: int) -> OpenPort | None:
        async with limit:
            result = await probe(ip, port, timeout)
            if result and port in TLS_PORTS:
                result = OpenPort(ip, port, result.banner, tls=await probe_tls(ip, port, timeout))
            return result

    ports = list(ports)
    tasks = [one(ip, port) for ip in ips for port in ports]
    return [r for r in await asyncio.gather(*tasks) if r]
