
import hashlib
import hmac
import json
import secrets
from pathlib import Path

from fileguard.hasher import calculate_sha256


def scan_directory(directory: Path) -> dict[str, str]:
    """Return relative file paths and their SHA-256 hashes."""
    directory = directory.resolve()

    if not directory.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    files: dict[str, str] = {}

    for path in sorted(directory.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue

        relative_path = path.relative_to(directory).as_posix()
        files[relative_path] = calculate_sha256(path)

    return files


def _canonical_json(data: dict[str, str]) -> bytes:
    """Serialize data consistently before calculating its HMAC."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _load_or_create_key(key_path: Path) -> bytes:
    """Load an existing secret key or create a new 256-bit key."""
    try:
        with key_path.open("xb") as file:
            key = secrets.token_bytes(32)
            file.write(key)
    except FileExistsError:
        key = key_path.read_bytes()

    if len(key) != 32:
        raise ValueError("Invalid key: expected exactly 32 bytes.")

    return key


def _validate_files(files: object) -> dict[str, str]:
    """Validate the file entries in a baseline."""
    if not isinstance(files, dict):
        raise ValueError("Invalid baseline: expected a files object.")

    for path, digest in files.items():
        if (
            not isinstance(path, str)
            or not path
            or path.startswith("/")
            or "\\" in path
            or any(part in ("", ".", "..") for part in path.split("/"))
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise ValueError("Invalid baseline entry.")

    return files


def create_baseline(
    directory: Path,
    baseline_path: Path,
    key_path: Path,
) -> dict[str, str]:
    """Create a baseline protected by HMAC-SHA-256."""
    directory = directory.resolve()
    baseline_path = baseline_path.resolve()
    key_path = key_path.resolve()

    if not directory.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    if baseline_path == key_path:
        raise ValueError("The baseline and key must use different files.")

    for path, label in (
        (baseline_path, "baseline"),
        (key_path, "key"),
    ):
        try:
            path.relative_to(directory)
        except ValueError:
            pass
        else:
            raise ValueError(
                f"The {label} file must be outside the monitored directory."
            )

    files = scan_directory(directory)
    key = _load_or_create_key(key_path)

    signature = hmac.new(
        key,
        _canonical_json(files),
        hashlib.sha256,
    ).hexdigest()

    document = {
        "version": 1,
        "files": files,
        "hmac_sha256": signature,
    }

    with baseline_path.open("w", encoding="utf-8") as file:
        json.dump(document, file, indent=4, ensure_ascii=False)

    return files


def load_baseline(
    baseline_path: Path,
    key_path: Path,
) -> dict[str, str]:
    """Load a baseline and verify its HMAC before trusting its contents."""
    with baseline_path.open("r", encoding="utf-8") as file:
        document = json.load(file)

    if not isinstance(document, dict) or document.get("version") != 1:
        raise ValueError("Invalid baseline format or unsupported version.")

    files = _validate_files(document.get("files"))
    signature = document.get("hmac_sha256")

    if (
        not isinstance(signature, str)
        or len(signature) != 64
        or any(char not in "0123456789abcdef" for char in signature)
    ):
        raise ValueError("Invalid baseline signature.")

    key = key_path.read_bytes()

    if len(key) != 32:
        raise ValueError("Invalid key: expected exactly 32 bytes.")

    expected_signature = hmac.new(
        key,
        _canonical_json(files),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_signature):
        raise ValueError(
            "Baseline integrity check failed. The baseline may have been modified."
        )

    return files


def compare_directories(
    directory: Path,
    baseline: dict[str, str],
) -> dict[str, list[str]]:
    """Compare the current directory state against a baseline."""
    current = scan_directory(directory)

    baseline_paths = set(baseline)
    current_paths = set(current)

    added = sorted(current_paths - baseline_paths)
    deleted = sorted(baseline_paths - current_paths)
    modified = sorted(
        path
        for path in baseline_paths & current_paths
        if baseline[path] != current[path]
    )
    unchanged = sorted(
        path
        for path in baseline_paths & current_paths
        if baseline[path] == current[path]
    )

    return {
        "added": added,
        "modified": modified,
        "deleted": deleted,
        "unchanged": unchanged,
    }
