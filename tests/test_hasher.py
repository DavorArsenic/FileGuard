import hashlib

from fileguard.hasher import calculate_sha256


def test_calculate_sha256(tmp_path):
    file_path = tmp_path / "example.txt"
    content = b"Hello, FileGuard!"

    file_path.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()

    assert calculate_sha256(file_path) == expected


def test_hash_changes_when_file_changes(tmp_path):
    file_path = tmp_path / "example.txt"

    file_path.write_text("Original content", encoding="utf-8")
    original_hash = calculate_sha256(file_path)

    file_path.write_text("Modified content", encoding="utf-8")
    modified_hash = calculate_sha256(file_path)

    assert original_hash != modified_hash
