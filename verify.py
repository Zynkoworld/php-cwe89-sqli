#!/usr/bin/env python3
"""verify.py — CI gate for the php×CWE-89 SQL-injection oracle. Runs the deterministic oracle over the
labelled DISCRIMINATING probe corpus (vuln + safe); exits 0 IFF recall==1.0 AND FP==0 AND non-degenerate."""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "oracle"))
import php_cwe89_sqli as oracle  # noqa: E402
if __name__ == "__main__":
    probes = os.path.join(os.path.dirname(os.path.abspath(__file__)), "probes", "probes.jsonl")
    sys.exit(oracle._run_probes(sys.argv[1] if len(sys.argv) > 1 else probes))
