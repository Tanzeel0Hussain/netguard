import sqlite3

import pytest

from netguard.storage import MIGRATIONS, SCHEMA_VERSION, Store


def test_new_database_gets_the_latest_schema(tmp_path):
    db = tmp_path / "netguard.db"
    Store(db).close()
    conn = sqlite3.connect(db)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"devices", "scans", "alerts", "events"} <= tables


def test_version_1_database_is_upgraded_and_keeps_its_data(tmp_path):
    db = tmp_path / "netguard.db"
    conn = sqlite3.connect(db)
    conn.executescript(MIGRATIONS[0] + "PRAGMA user_version = 1;")
    conn.execute(
        "INSERT INTO devices (mac, ip, first_seen, last_seen, trusted, label) "
        "VALUES ('aa:aa:aa:aa:aa:01', '192.168.1.10', '2026-10-01T12:00:00+00:00', "
        "'2026-10-01T12:00:00+00:00', 1, 'My phone')"
    )
    conn.commit()
    conn.close()

    with Store(db) as store:
        phone = store.device("aa:aa:aa:aa:aa:01")
        assert (phone.label, phone.trusted, phone.present) == ("My phone", True, True)
        assert store.events() == []


def test_database_from_a_newer_version_is_refused(tmp_path):
    db = tmp_path / "netguard.db"
    conn = sqlite3.connect(db)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    conn.close()
    with pytest.raises(RuntimeError, match="newer NetGuard"):
        Store(db)
