
import json

from main import main
from fileguard.monitor import create_baseline


def test_baseline_command(tmp_path, monkeypatch, capsys):
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    (monitored / "example.txt").write_text("original", encoding="utf-8")

    baseline_path = tmp_path / "baseline.json"
    key_path = tmp_path / "secret.key"

    monkeypatch.setattr(
        "sys.argv",
        [
            "main.py",
            "baseline",
            "--directory",
            str(monitored),
            "--baseline",
            str(baseline_path),
            "--key",
            str(key_path),
        ],
    )

    main()

    output = capsys.readouterr().out

    assert "Baseline created successfully: 1 files recorded." in output
    assert baseline_path.exists()
    assert key_path.exists()

    document = json.loads(baseline_path.read_text(encoding="utf-8"))

    assert document["version"] == 1
    assert "example.txt" in document["files"]
    assert len(document["hmac_sha256"]) == 64


def test_scan_command_detects_added_file(tmp_path, monkeypatch, capsys):
    monitored = tmp_path / "monitored"
    monitored.mkdir()

    baseline_path = tmp_path / "baseline.json"
    key_path = tmp_path / "secret.key"

    # Create a valid baseline while the directory is empty.
    create_baseline(monitored, baseline_path, key_path)

    # Add a file after the baseline was created.
    (monitored / "new.txt").write_text("new content", encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        [
            "main.py",
            "scan",
            "--directory",
            str(monitored),
            "--baseline",
            str(baseline_path),
            "--key",
            str(key_path),
        ],
    )

    main()

    output = capsys.readouterr().out

    assert "ADDED (1):" in output
    assert "new.txt" in output
    assert "MODIFIED (0):" in output
    assert "DELETED (0):" in output


def test_scan_command_exports_json_report(tmp_path, monkeypatch, capsys):
    monitored = tmp_path / "monitored"
    monitored.mkdir()

    baseline_path = tmp_path / "baseline.json"
    key_path = tmp_path / "secret.key"
    report_path = tmp_path / "report.json"

    # Create a valid baseline for an empty directory.
    create_baseline(monitored, baseline_path, key_path)

    monkeypatch.setattr(
        "sys.argv",
        [
            "main.py",
            "scan",
            "--directory",
            str(monitored),
            "--baseline",
            str(baseline_path),
            "--key",
            str(key_path),
            "--report",
            str(report_path),
        ],
    )

    main()

    output = capsys.readouterr().out
    assert "JSON report saved to:" in output

    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report["summary"]["added"] == 0
    assert report["summary"]["modified"] == 0
    assert report["summary"]["deleted"] == 0
    assert report["summary"]["unchanged"] == 0
    assert "timestamp" in report
