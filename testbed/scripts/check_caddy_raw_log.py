"""Check newly written Caddy raw logs, not only the converted JSONL.

Run inside caddy-log: python -I - FROM < check_caddy_raw_log.py
Existing records before FROM are not rewritten or deleted.
"""
import json
import sys
from pathlib import Path


def check_record(record):
    request = record.get("request", {})
    errors = []
    if "?" in str(request.get("uri", "")):
        errors.append("query retained")
    if "headers" in request or "resp_headers" in record:
        errors.append("headers retained")
    return errors


def main():
    first = int(sys.argv[1])
    lines = Path("/in/access.json").read_bytes().splitlines(keepends=True)
    selected = lines[first - 1:]
    errors = []
    if not selected:
        errors.append("no new raw records")
    for number, line in enumerate(selected, first):
        if not line.endswith(b"\n"):
            errors.append(f"line {number}: incomplete record")
            continue
        try:
            errors.extend(f"line {number}: {error}" for error in check_record(json.loads(line)))
        except (ValueError, AttributeError, TypeError):
            errors.append(f"line {number}: invalid JSON record")
    print(f"raw_records={len(selected)} errors={len(errors)}")
    for error in errors:
        print("ERR", error)  # never print request contents or secret values
    return bool(errors)


if __name__ == "__main__":
    sys.exit(main())
