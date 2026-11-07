from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

from proxy_probe.models import RESULT_BLOCK, RESULT_DEAD, RESULT_OK, Server
from proxy_probe.orchestrator import gather_sources
from proxy_probe.reporter import write_import_file, write_report
from proxy_probe.throne import read_groups, read_profiles_for_group


def test_read_groups_ui_order(tmp_path: Path) -> None:
    db_file = tmp_path / "throne.db"
    con = sqlite3.connect(str(db_file))
    con.execute(
        "CREATE TABLE groups ("
        "id INTEGER PRIMARY KEY, name TEXT, url TEXT, sub_options_json TEXT, archive INTEGER DEFAULT 0)"
    )
    con.execute("CREATE TABLE groups_order (group_id INTEGER PRIMARY KEY, display_order INTEGER)")

    # Insert groups with IDs 1, 2, 3
    con.execute("INSERT INTO groups (id, name, url, archive) VALUES (1, 'Group 1', '', 0)")
    con.execute("INSERT INTO groups (id, name, url, archive) VALUES (2, 'Group 2', '', 0)")
    con.execute("INSERT INTO groups (id, name, url, archive) VALUES (3, 'Group 3', '', 0)")

    # Order: Group 3 (order 0), Group 1 (order 1), Group 2 (order 2)
    con.execute("INSERT INTO groups_order (group_id, display_order) VALUES (3, 0)")
    con.execute("INSERT INTO groups_order (group_id, display_order) VALUES (1, 1)")
    con.execute("INSERT INTO groups_order (group_id, display_order) VALUES (2, 2)")
    con.commit()
    con.close()

    with patch("proxy_probe.throne.get_db_snapshot", return_value=db_file):
        groups = read_groups()
        assert [g["id"] for g in groups] == [3, 1, 2]


def test_read_profiles_for_group_ui_order(tmp_path: Path) -> None:
    db_file = tmp_path / "throne.db"
    con = sqlite3.connect(str(db_file))
    con.execute(
        "CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT, profiles_json TEXT, archive INTEGER DEFAULT 0)"
    )
    con.execute(
        "CREATE TABLE profiles (id INTEGER PRIMARY KEY, gid INTEGER, type TEXT, name TEXT, outbound_json TEXT)"
    )

    # Group has profiles ordered as: [30, 10, 20]
    con.execute(
        "INSERT INTO groups (id, name, profiles_json) VALUES (1, 'Test Group', ?)",
        (json.dumps([30, 10, 20]),),
    )

    obj_template = json.dumps({"type": "vless", "server": "1.2.3.4", "server_port": 443})
    sql = "INSERT INTO profiles (id, gid, type, name, outbound_json) VALUES (?, 1, 'sing-box', ?, ?)"
    con.execute(sql, (10, "Profile 10", obj_template))
    con.execute(sql, (20, "Profile 20", obj_template))
    con.execute(sql, (30, "Profile 30", obj_template))
    con.commit()
    con.close()

    with patch("proxy_probe.throne.get_db_snapshot", return_value=db_file):
        servers = read_profiles_for_group(1, "Test Group")
        # Should be ordered strictly matching profiles_json: 30, 10, 20
        assert [s.name for s in servers] == ["Profile 30", "Profile 10", "Profile 20"]


def test_gather_sources_preserves_ui_order() -> None:
    # Groups in specific UI order: 14, 9, 2
    groups = [
        {"id": 14, "name": "Group 14", "url": ""},
        {"id": 9, "name": "Group 9", "url": ""},
        {"id": 2, "name": "Group 2", "url": ""},
    ]

    def mock_read_profiles(gid: int, gname: str) -> list[Server]:
        obj = {"type": "vless", "server": f"10.0.{gid}.1", "server_port": 443}
        return [
            Server(
                group_id=gid,
                group_name=gname,
                name=f"Server in {gname}",
                engine="sing-box",
                server=f"10.0.{gid}.1",
                server_port=443,
                import_obj=obj,
                source="db",
            )
        ]

    with patch("proxy_probe.orchestrator.read_profiles_for_group", side_effect=mock_read_profiles):
        selected = {14, 9, 2}
        servers, _ = gather_sources(groups, selected, no_fetch=True)
        # Should strictly preserve groups list order (14, 9, 2) rather than sorted(selected) (2, 9, 14)
        assert [s.group_id for s in servers] == [14, 9, 2]


def test_write_report_ui_order(tmp_path: Path) -> None:
    rep_file = tmp_path / "report.md"
    s1 = Server(1, "G1", "S1", "sing-box", "1.1.1.1", 443, {}, "fresh", index=1, result=RESULT_DEAD)
    s2 = Server(1, "G1", "S2", "sing-box", "2.2.2.2", 443, {}, "fresh", index=2, result=RESULT_OK)
    s3 = Server(1, "G1", "S3", "sing-box", "3.3.3.3", 443, {}, "fresh", index=3, result=RESULT_BLOCK)

    # In UI, order was 1 (DEAD), 2 (OK), 3 (BLOCK)
    write_report(
        servers=[s1, s2, s3],
        report_path=rep_file,
        ver_sb="1.0",
        ver_xr="2.0",
        warnings=[],
        time_s=1.0,
    )
    content = rep_file.read_text(encoding="utf-8")
    pos1 = content.find("| 1 | DEAD |")
    pos2 = content.find("| 2 | AGY-OK |")
    pos3 = content.find("| 3 | AGY-BLOCK |")
    assert pos1 != -1 and pos2 != -1 and pos3 != -1
    # UI order must be strictly preserved: 1, then 2, then 3
    assert pos1 < pos2 < pos3


def test_write_import_file_ui_order(tmp_path: Path) -> None:
    import_file = tmp_path / "proxy-ok.txt"
    obj1 = {"type": "vless", "server": "9.9.9.9", "server_port": 443}
    obj2 = {"type": "vless", "server": "1.1.1.1", "server_port": 443}
    # s1 has IP 9.9.9.9 (index 1), s2 has IP 1.1.1.1 (index 2)
    s1 = Server(1, "G1", "Node A", "sing-box", "9.9.9.9", 443, obj1, "fresh", index=1, result=RESULT_OK)
    s2 = Server(1, "G1", "Node B", "sing-box", "1.1.1.1", 443, obj2, "fresh", index=2, result=RESULT_OK)

    write_import_file(cache=None, path=import_file, fallback_servers=[s1, s2])
    content = import_file.read_text(encoding="utf-8")
    lines = [json.loads(line) for line in content.strip().split("\n")]
    assert len(lines) == 1  # sing-box stream
    configs = lines[0]
    assert len(configs) == 2
    # First must be 9.9.9.9 (Node A), second 1.1.1.1 (Node B) matching s.index UI order, NOT sorted by host!
    assert configs[0]["server"] == "9.9.9.9"
    assert configs[1]["server"] == "1.1.1.1"
