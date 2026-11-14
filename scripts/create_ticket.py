import csv
import json
import os
import sys

CSV_FILE = "tickets.csv"


def get_severity(count):
    if count >= 200:
        return "Critical"
    elif count >= 50:
        return "High"
    elif count >= 10:
        return "Medium"
    else:
        return "Low"


def main():
    # Step 13: the alert file name comes from the command line
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/create_ticket.py <alert.json>")
        sys.exit(1)
    alert_file = sys.argv[1]

    # Step 12: handle a missing file or bad JSON
    try:
        with open(alert_file) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: file '{alert_file}' not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: '{alert_file}' is not valid JSON.")
        sys.exit(1)

    # Step 12: handle missing fields or a non-numeric count
    try:
        result = data["result"]
        src_ip = result["src_ip"]
        timestamp = result["_time"]
        attempts = int(result["attempts"])
    except (KeyError, ValueError, TypeError) as e:
        print(f"Error: alert is missing a field or has a bad value ({e}).")
        sys.exit(1)

    severity = get_severity(attempts)

    # Step 11: append one row to tickets.csv, header only on a new file
    file_exists = os.path.exists(CSV_FILE)
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "source_ip", "severity", "attempts"])
        writer.writerow([timestamp, src_ip, severity, attempts])

    print(f"Ticket created: {src_ip} | {severity} | {attempts} attempts")


main()"


