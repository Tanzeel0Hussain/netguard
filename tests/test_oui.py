import http.server
import threading

import pytest

from netguard.models import is_randomized_mac
from netguard.oui import DownloadError, VendorDB, download

# A few real lines in Wireshark's manuf format, including a /28 and a /36 block.
MANUF = """\
# Wireshark manuf sample
00:00:0C\tCisco\tCisco Systems, Inc
8C:6D:77\tHuawei\tHuawei Technologies Co.,Ltd
70:B3:D5\tIEEERegi\tIEEE Registration Authority
70:B3:D5:F2:F0:00/36\tTelepor\tTeleport Pty Ltd
00:55:DA:00:00:00/28\tShinkoTe\tShinko Technos co.,ltd.
04:88:5F\tHuawei
00:00:01         \tXerox       \tXerox Corporation
not a valid line
"""


def test_lookup_uses_the_long_name_and_falls_back_to_the_short_one():
    db = VendorDB.from_text(MANUF)
    assert db.lookup("00:00:0c:12:34:56") == "Cisco Systems, Inc"
    assert db.lookup("04:88:5f:12:34:56") == "Huawei"
    assert db.lookup("de:ad:be:ef:00:01") is None
    assert len(db) == 7


def test_columns_padded_with_spaces_are_parsed():
    # Wireshark's real file pads columns with spaces before each tab.
    db = VendorDB.from_text(MANUF)
    assert db.lookup("00:00:01:aa:bb:cc") == "Xerox Corporation"


def test_longest_prefix_wins():
    db = VendorDB.from_text(MANUF)
    assert db.lookup("70:b3:d5:f2:f0:42") == "Teleport Pty Ltd"  # inside the /36 block
    assert db.lookup("70:b3:d5:00:00:01") == "IEEE Registration Authority"
    assert db.lookup("00:55:da:01:02:03") == "Shinko Technos co.,ltd."  # /28


def test_missing_file_gives_an_empty_database(tmp_path):
    db = VendorDB.load(tmp_path / "nope")
    assert len(db) == 0
    assert db.lookup("00:00:0c:12:34:56") is None


@pytest.mark.parametrize(
    ("mac", "randomized"),
    [
        ("6e:11:22:33:44:73", True),
        ("fe:11:22:33:44:74", True),
        ("02:00:00:00:00:01", True),
        ("8c:6d:77:ab:cd:01", False),
        ("00:00:0c:12:34:56", False),
    ],
)
def test_randomized_mac(mac, randomized):
    assert is_randomized_mac(mac) is randomized


# --- download, against a local HTTP server --------------------------------

BODY = MANUF.encode()


@pytest.fixture
def server():
    """A tiny HTTP server. `state.fail` lists status codes to answer first."""
    state = type("State", (), {"fail": [], "honor_range": True, "requests": []})()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            state.requests.append(self.headers.get("Range"))
            if self.path != "/manuf":
                self.send_error(404)
                return
            if state.fail:
                self.send_error(state.fail.pop(0))
                return
            start = 0
            rng = self.headers.get("Range")
            if rng and state.honor_range:
                start = int(rng.removeprefix("bytes=").rstrip("-"))
                if start >= len(BODY):
                    self.send_error(416)
                    return
                self.send_response(206)
            else:
                self.send_response(200)
            self.send_header("Content-Length", str(len(BODY) - start))
            self.end_headers()
            self.wfile.write(BODY[start:])

        def log_message(self, *args):
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    state.url = f"http://127.0.0.1:{httpd.server_port}"
    yield state
    httpd.shutdown()


def test_download_saves_the_file(server, tmp_path):
    dest = download(f"{server.url}/manuf", tmp_path / "manuf", sleep=lambda s: None)
    assert dest.read_bytes() == BODY
    assert not (tmp_path / "manuf.part").exists()


def test_download_resumes_a_partial_file(server, tmp_path):
    (tmp_path / "manuf.part").write_bytes(BODY[:40])
    download(f"{server.url}/manuf", tmp_path / "manuf", sleep=lambda s: None)
    assert server.requests == ["bytes=40-"]
    assert (tmp_path / "manuf").read_bytes() == BODY


def test_download_starts_over_if_the_server_ignores_range(server, tmp_path):
    server.honor_range = False
    (tmp_path / "manuf.part").write_bytes(b"garbage from an old attempt")
    download(f"{server.url}/manuf", tmp_path / "manuf", sleep=lambda s: None)
    assert (tmp_path / "manuf").read_bytes() == BODY


def test_download_retries_server_errors(server, tmp_path):
    server.fail = [503, 502]
    waits = []
    download(f"{server.url}/manuf", tmp_path / "manuf", sleep=waits.append)
    assert waits == [2, 4]  # exponential backoff
    assert (tmp_path / "manuf").read_bytes() == BODY


def test_download_does_not_retry_a_404(server, tmp_path):
    with pytest.raises(DownloadError, match="HTTP 404"):
        download(f"{server.url}/missing", tmp_path / "manuf", sleep=lambda s: None)
    assert len(server.requests) == 1


def test_download_gives_up_after_the_last_retry(server, tmp_path):
    server.fail = [503] * 3
    with pytest.raises(DownloadError, match="HTTP 503"):
        download(f"{server.url}/manuf", tmp_path / "manuf", retries=3, sleep=lambda s: None)
