
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from fileguard.monitor import (
    compare_directories,
    create_baseline,
    load_baseline,
)


def main():
    parser = argparse.ArgumentParser(
        description="FileGuard - File Integrity Monitoring Tool"
    )

    parser.add_argument(
        "command",
        choices=["baseline", "scan"],
        help="Create a baseline or scan for file changes",
    )

    parser.add_argument(
        "--directory",
        type=Path,
        default=Path("monitored_files"),
        help="Directory to monitor (default: monitored_files)",
    )

    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path(".baseline.json"),
        help="Path to the baseline JSON file",
    )

    parser.add_argument(
        "--key",
        type=Path,
        default=Path(".fileguard.key"),
        help="Path to the secret HMAC key file",
    )

    parser.add_argument(
        "--report",
        type=Path,
        help="Optional path for exporting scan results as JSON",
    )

    args = parser.parse_args()

    try:
        if args.command == "baseline":
            baseline = create_baseline(
                args.directory,
                args.baseline,
                args.key,
            )
            print(
                f"Baseline created successfully: "
                f"{len(baseline)} files recorded."
            )

        elif args.command == "scan":
            baseline = load_baseline(args.baseline, args.key)
            changes = compare_directories(args.directory, baseline)

            for category in ("added", "modified", "deleted", "unchanged"):
                files = changes[category]
                print(f"\n{category.upper()} ({len(files)}):")

                for file_path in files:
                    print(f"  {file_path}")

            if args.report:
                report = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "directory": str(args.directory.resolve()),
                    "summary": {
                        category: len(files)
                        for category, files in changes.items()
                    },
                    "changes": changes,
                }

                with args.report.open("w", encoding="utf-8") as file:
                    json.dump(
                        report,
                        file,
                        indent=4,
                        ensure_ascii=False,
                    )

                print(f"\nJSON report saved to: {args.report}")

    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
