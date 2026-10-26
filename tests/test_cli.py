import pytest

from netguard import cli
from tests.conftest import obs

PHONE = "aa:aa:aa:aa:aa:01"
STRANGER = "de:ad:be:ef:00:01"


@pytest.fixture
def run(tmp_path, monkeypatch, capsys):
    """Run `netguard` with a throwaway database and fake discovery results."""
    monkeypatch.setenv("HOME", str(tmp_path))  # never read the real config file
    db = tmp_path / "netguard.db"
    found = []
    monkeypatch.setattr(cli, "discover", lambda *a, **kw: list(found))

    def _run(*args):
        code = cli.main(["--db", str(db), *args])
        out, err = capsys.readouterr()
        return code, out, err

    _run.found = found
    return _run


def test_scan_then_list_trust_and_alerts(run):
    run.found[:] = [obs("192.168.1.10", PHONE)]
    code, out, _ = run("scan", "--network", "192.168.1.0/24")
    assert code == 0
    assert "Found 1 device(s)." in out
    assert "First scan" in out

    code, out, _ = run("trust", "AA-AA-AA-AA-AA-01", "--label", "My phone")
    assert code == 0
    assert f"{PHONE} marked as trusted." in out

    run.found[:] = [obs("192.168.1.10", PHONE), obs("192.168.1.66", STRANGER)]
    code, out, _ = run("scan", "--network", "192.168.1.0/24")
    assert f"[!] Unknown device joined: {STRANGER} at 192.168.1.66" in out
    assert "NEW" in out

    code, out, _ = run("devices", "--untrusted")
    assert STRANGER in out and PHONE not in out

    code, out, _ = run("alerts")
    assert "WARNING" in out and STRANGER in out


def test_scan_refuses_a_public_network(run):
    code, _, err = run("scan", "--network", "8.8.8.0/24")
    assert code == 1
    assert "not a private network" in err


def test_trust_unknown_mac_fails(run):
    code, _, err = run("trust", STRANGER)
    assert code == 1
    assert "not in the inventory" in err


def test_invalid_mac_is_reported(run):
    code, _, err = run("trust", "not-a-mac")
    assert code == 1
    assert "not a valid MAC" in err
