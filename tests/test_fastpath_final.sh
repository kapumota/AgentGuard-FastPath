#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
make all >/tmp/agfast-final-build.log
./bin/agfast analyze examples/events.jsonl --policy examples/policy.json --risk --window-events 3 --report /tmp/agfast-final-report.json --html /tmp/agfast-final-report.html --alerts-csv /tmp/agfast-final-alerts.csv >/tmp/agfast-final-analyze.txt || test $? -eq 2
./bin/agfast stats examples/events_day2.jsonl --window-events 50 --report /tmp/agfast-final-stats.json >/tmp/agfast-final-stats.txt
./bin/agfast check-ip 45.90.10.2 --policy examples/policy.json --delete-test --report /tmp/agfast-final-cuckoo.json >/tmp/agfast-final-cuckoo.txt
./bin/agfast similarity examples/events_day3.jsonl --process python --compare-process bash --policy examples/policy.json --report /tmp/agfast-final-similarity.json >/tmp/agfast-final-similarity.txt
./bin/agfast tail examples/events.jsonl --policy examples/policy.json >/tmp/agfast-final-tail.txt
python3 -m json.tool /tmp/agfast-final-report.json >/dev/null
python3 -m json.tool /tmp/agfast-final-stats.json >/dev/null
python3 -m json.tool /tmp/agfast-final-cuckoo.json >/dev/null
python3 -m json.tool /tmp/agfast-final-similarity.json >/dev/null
grep -q "Space-Saving" /tmp/agfast-final-stats.txt
grep -q "Cuckoo tras borrado" /tmp/agfast-final-cuckoo.txt
grep -q "Odd Sketch" /tmp/agfast-final-similarity.txt
grep -q "CRITICAL" /tmp/agfast-final-tail.txt
echo "OK: pruebas finales FastPath"
