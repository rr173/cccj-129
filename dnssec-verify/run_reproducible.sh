#!/usr/bin/env bash
# Reproducible end-to-end runner for the offline DNSSEC verifier.
#
# Builds signed fixtures, loads them into a WAL SQLite store, runs the unit
# and scenario suites (the latter cross-checked against the independent
# dnspython oracle), then the 100k+ record scale test with peak-memory and
# read-only checks.  Everything runs under Python isolated mode (-I).
set -euo pipefail

cd "$(dirname "$0")"
PYTHON=python3

echo "==================================================================="
echo " 1/5  Generate cryptographically signed zone fixtures"
echo "==================================================================="
$PYTHON -I tests/build_fixtures.py

echo
echo "==================================================================="
echo " 2/5  Load every fixture snapshot into the WAL SQLite store"
echo "==================================================================="
$PYTHON -I tests/load_all_fixtures.py

echo
echo "==================================================================="
echo " 3/5  Protocol unit tests (key tag / DS / RRSIG / canonical forms)"
echo "==================================================================="
$PYTHON -I tests/run_unit_tests.py

echo
echo "==================================================================="
echo " 4/5  Scenario suite vs. independent dnspython oracle"
echo "==================================================================="
$PYTHON -I tests/run_all_tests.py

echo
echo "==================================================================="
echo " 5/5  100k+ historical-record scale, memory and read-only test"
echo "==================================================================="
$PYTHON -I tests/build_large.py
$PYTHON -I tests/run_large_test.py

echo
echo "All reproducible checks completed successfully."
