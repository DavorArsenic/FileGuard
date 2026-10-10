# FileGuard

**File integrity monitoring tool built with Python.**

FileGuard is a command-line security tool that monitors files for unauthorized or unexpected changes. It uses SHA-256 hashing to detect changes in file contents and HMAC-SHA-256 to verify the integrity of its stored baseline.

## Features

- **File integrity monitoring** — detects added, modified, and deleted files.
- **SHA-256 hashing** — calculates cryptographic hashes of file contents.
- **Baseline verification** — uses HMAC-SHA-256 to detect unauthorized modifications to the baseline.
- **JSON reports** — exports scan results with timestamps and change summaries.
- **Automated tests** — includes tests for hashing, change detection, baseline validation, and CLI commands.
- **Command-line interface** — supports baseline creation and directory scanning.

## Technologies

- Python 3
- SHA-256
- HMAC-SHA-256
- JSON
- pytest

## Project Structure

```text
fileguard/
|-- fileguard/
|   |-- __init__.py
|   |-- cli.py
|   |-- hasher.py
|   |-- monitor.py
|-- monitored_files/
|   |-- file.txt
|-- tests/
|   |-- test_cli.py
|   |-- test_hasher.py
|   |-- test_monitor.py
|-- .gitignore
|-- main.py
|-- README.md
```

## Requirements

- Python 3.10 or newer
- pip

## Installation

Clone the repository and navigate to the project directory:

```bash
git clone <REPOSITORY_URL>
cd fileguard
```

Create and activate a virtual environment.

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux/macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the testing dependency:

```bash
python -m pip install pytest
```

## Usage

### 1. Create a baseline

Place the files you want to monitor in `monitored_files/`, then run:

```bash
python main.py baseline
```

FileGuard calculates the SHA-256 hash of each file and stores the results in `.baseline.json`. It also creates `.fileguard.key`, which is used to authenticate the baseline with HMAC-SHA-256.

### 2. Scan for changes

```bash
python main.py scan
```

FileGuard compares the current directory contents with the baseline and reports four categories:

- **ADDED** — files not present in the baseline.
- **MODIFIED** — files whose contents have changed.
- **DELETED** — files that are no longer present.
- **UNCHANGED** — files whose contents match the baseline.

### 3. Export a JSON report

```bash
python main.py scan --report scan-report.json
```

The report includes a timestamp, the monitored directory, summary counts, and the detected file changes.

### 4. Run the tests

```bash
python -m pytest -v
```

## Security Considerations

FileGuard is a learning and portfolio project intended to demonstrate file integrity monitoring and basic cryptographic integrity verification.

- SHA-256 detects changes to file contents by comparing their hashes.
- HMAC-SHA-256 authenticates the baseline using a secret key.
- The baseline and secret key should be kept outside the monitored directory.
- The secret key must be protected separately from the baseline. If an attacker can modify both the baseline and its key, the integrity protection may be compromised.
- The `.gitignore` file excludes local baseline and key files from normal Git staging, but it does not protect files that were already committed.

FileGuard is not a complete endpoint detection system and does not prevent file modifications. It detects differences when a scan is performed.

## Testing

The test suite covers file hashing, change detection, baseline loading, rejection of tampered or invalid baselines, and command-line functionality.

## License

No license has been specified yet. All rights are reserved unless a license is added to this repository.
