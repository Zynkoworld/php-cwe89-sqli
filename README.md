# zynko-oracle · `php-cwe89-sqli`

**A deterministic, re-checkable SQL-injection (CWE-89) taint decider for PHP.**

An **oracle** *deterministically decides* the truth of a case — it doesn't guess, it decides. This one decides,
for a given piece of **PHP** code, whether it carries an **unsanitized taint flow from untrusted input into a
SQL query** (CWE-89, SQL injection).

## Proven
Measured on a **discriminating** probe set of **10 cases (5 vulnerable + 5 safe)** — verified by running the
oracle, not asserted:

| Metric | Value | Meaning |
|---|---|---|
| **Recall** | **1.0** | catches all 5 vulnerable cases |
| **False positives** | **0** | flags none of the 5 safe cases |
| **Byte-lock** | **✓** | deterministic — same input → same verdict, re-runnable anywhere |

## What it decides
- **Source:** untrusted input (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, …)
- **Sink:** SQL query construction (`mysqli_query`, `PDO::query`, `->query(...)`, …)
- **Sanitizer:** prepared / parameterised statements (`PDO::prepare` + bound params, `mysqli` bind_param)
- **Verdict:** `FLAG` (injection present) / `SAFE`

## Honest note — why publish this
SQL injection is **already well-covered** by existing tools (psalm, progpilot, semgrep). This oracle's value is
**not novelty but re-checkability:** a minimal, byte-locked, independently-implemented decider you can rerun and
verify yourself, cross-validated against an external snapshot. It **opens PHP** coverage in Zynko's capability
map — shared openly.

## Run it yourself
```
python3 verify.py
```
Prints a per-probe verdict + `recall / false_positives`, and **exits 0 iff `recall==1.0` and `FP==0`**.

## Scope (honest)
Per-domain: **single-function, straight-line PHP**; the probe corpus is **10 cases (5+5)**. "Proven" means
*proven on this stated set within this domain* — not a universal SQL-injection solver. Add probes (both kinds)
and re-run to extend it.

## License
**Apache-2.0** — free to use, including commercially.

---
Part of **[Zynko](https://zynko.dev)** — deterministic, provable AI.
Zynko doesn't guess — it *establishes truth*. See the full set: **https://zynko.dev/oracles.html**
