#!/bin/sh
set -eu

IDS_FILE="${1:-results/memrepair_failed_medium_subset/pending_ids.txt}"
LOG_FILE="${2:-results/memrepair_failed_medium_subset/run_failed_medium.log}"

if [ ! -f "$IDS_FILE" ]; then
  echo "IDs file not found: $IDS_FILE" >&2
  exit 1
fi

echo "Using IDs file: $IDS_FILE"
echo "Log file: $LOG_FILE"
echo "Start: $(date -u '+%Y-%m-%dT%H:%M:%SZ')" | tee -a "$LOG_FILE"

while IFS= read -r iid; do
  [ -z "$iid" ] && continue
  echo "=== running $iid ===" | tee -a "$LOG_FILE"
  python main.py --instance_id "$iid" 2>&1 | tee -a "$LOG_FILE"
done < "$IDS_FILE"

echo "Done: $(date -u '+%Y-%m-%dT%H:%M:%SZ')" | tee -a "$LOG_FILE"
