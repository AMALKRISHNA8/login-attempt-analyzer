
import argparse
import csv
from collections import Counter
from pathlib import Path


def analyze_logs(file_path, threshold):
    failed_attempts = Counter()
    total_failures = 0

    with file_path.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        required_columns = {"timestamp", "event", "username", "ip"}

        if not reader.fieldnames or not required_columns.issubset(reader.fieldnames):
            raise ValueError("CSV must contain: timestamp, event, username, ip")

        for row in reader:
            event = (row.get("event") or "").strip().upper()
            ip = (row.get("ip") or "").strip()

            if event == "FAILED_LOGIN" and ip:
                failed_attempts[ip] += 1
                total_failures += 1

    print("\n===== LOGIN ATTEMPT ANALYZER =====")
    print(f"Total failed login attempts: {total_failures}")

    if not failed_attempts:
        print("No failed login attempts found.")
        return

    print("\nIP Address Analysis:")

    for ip, count in failed_attempts.most_common():
        print(f"{ip}: {count} failed attempts")

        if count >= threshold:
            print("  [ALERT] Suspicious login activity detected!")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze failed login attempts from CSV logs."
    )
    parser.add_argument("file", help="Path to the CSV log file")
    parser.add_argument(
        "--threshold", type=int, default=3,
        help="Failed attempts needed to trigger an alert (default: 3)"
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("Threshold must be at least 1.")

    try:
        analyze_logs(Path(args.file), args.threshold)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
