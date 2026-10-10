
import json

import pytest

from fileguard.monitor import (
    compare_directories,
    create_baseline,
    load_baseline,
)


def test_detects_file_changes(tmp_path):
    monitored = tmp_path / "monitored"
    monitored.mkdir()

    (monitored / "keep.txt").write_text("same", encoding="utf-8")
    (monitored / "change.txt").write_text("original", encoding="utf-8")
    (monitored / "delete.txt").write_text("remove me", encoding="utf-8")

    baseline_path = tmp_path / "baseline.json"
    key_path = tmp_path / "secret.key"

    baseline = create_baseline(monitored, baseline_path, key_path)

    (monitored / "change.txt").write_text("modified", encoding="utf-8")
    (monitored / "delete.txt").unlink()
    (monitored / "new.txt").write_text("new file", encoding="utf-8")

    result = compare_directories(monitored, baseline)

    assert result["added"] == ["new.txt"]
    assert result["modified"] == ["change.txt"]
    assert result["deleted"] == ["delete.txt"]
    assert result["unchanged"] == ["keep.txt"]


def test_load_baseline(tmp_path):
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    (monitored / "example.txt").write_text("content", encoding="utf-8")

    baseline_path = tmp_path / "baseline.json"
    key_path = tmp_path / "secret.key"

    created = create_baseline(monitored, baseline_path, key_path)

    assert load_baseline(baseline_path, key_path) == created


def test_rejects_tampered_baseline(tmp_path):
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    (monitored / "example.txt").write_text("content", encoding="utf-8")

    baseline_path = tmp_path / "baseline.json"
    key_path = tmp_path / "secret.key"

    create_baseline(monitored, baseline_path, key_path)

    document = json.loads(baseline_path.read_text(encoding="utf-8"))
    document["files"]["example.txt"] = "a" * 64
    baseline_path.write_text(
        json.dumps(document),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="integrity check failed"):
        load_baseline(baseline_path, key_path)


def test_rejects_invalid_baseline(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    key_path = tmp_path / "secret.key"

    baseline_path.write_text(
        json.dumps({"example.txt": "invalid"}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_baseline(baseline_path, key_path)


def test_baseline_must_be_outside_monitored_directory(tmp_path):
    monitored = tmp_path / "monitored"
    monitored.mkdir()

    with pytest.raises(ValueError):
        create_baseline(
            monitored,
            monitored / "baseline.json",
            tmp_path / "secret.key",
        )
