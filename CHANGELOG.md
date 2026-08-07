# Changelog

Deterministic and byte-locked: a released version's verdicts are reproducible forever (re-check with `verify.py`).

## [1.0.0] — 2026-08-07
### Added
- First release: `php-cwe89-sqli` — a deterministic SQL-injection (CWE-89) taint decider for PHP.
- **Proven**: **recall 1.0 · false-positives 0** on **10 discriminating probes (5 vulnerable + 5 safe)**, byte-locked.
- Opens PHP coverage in Zynko's capability map; cross-validated against an external snapshot.
