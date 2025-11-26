import json
import csv
import sys
from typing import List, Dict


def parse_waf_log_line(line: str) -> Dict:
    """
    Parse a single WAF log line (JSON) and extract key fields.

    This is intentionally generic. Adapt the keys to match your
    BIG-IP / logging format (e.g., Splunk, Elastic, etc.).
    """
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return {}

    return {
        "timestamp": data.get("timestamp") or data.get("event_timestamp"),
        "client_ip": data.get("ip_client") or data.get("clientIp"),
        "method": data.get("http_method") or data.get("method"),
        "uri": data.get("uri") or data.get("request_uri"),
        "violation": data.get("violation") or data.get("violation_name"),
        "support_id": data.get("support_id") or data.get("supportId"),
    }


def parse_waf_log_file(input_path: str, output_path: str) -> None:
    """Read JSON-lines WAF log file and export selected fields to CSV."""
    rows: List[Dict] = []

    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            parsed = parse_waf_log_line(line.strip())
            if parsed:
                rows.append(parsed)

    if not rows:
        print("No valid WAF log entries found.")
        return

    fieldnames = list(rows[0].keys())

    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Exported {len(rows)} rows to {output_path}")


def main() -> None:
    if len(sys.argv) != 3:
        print("Usage: python waf_log_parser.py <input.json> <output.csv>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    parse_waf_log_file(input_path, output_path)


if __name__ == "__main__":
    main()
