#!/usr/bin/env python3
"""php_cwe89_sqli — a deterministic oracle for SQL injection (CWE-89) in PHP.

An oracle *decides* the truth of a case; it does not guess. Given a piece of PHP code, this decides whether
untrusted input reaches a SQL query STRING unsanitized (CWE-89):

  SOURCE     $_GET[...], $_POST[...], $_REQUEST[...], $_COOKIE[...], $_SERVER[...], file_get_contents('php://input')
  SINK       SQL execution: mysqli_query, mysql_query, pg_query, $x->query(...), $x->exec(...), $x->multi_query(...)
  SAFE       a PREPARED STATEMENT ($x->prepare("... ?"/":name") + bind_param/bindParam/bindValue/execute),
             or a fully constant query. Bound parameters are the safe channel.
  VERDICT    "FLAG"  user input reaches the query string via PHP string CONCATENATION (.) or double-quote
                     INTERPOLATION ("... $var ...")  -> SQL injection present
             "SAFE"  parameterised / constant

Deterministic, standard-library only (re, sys), re-runnable. Lightweight source-level taint over `$var`
assignments; the SQL-relevant distinction is *query-string* taint (dangerous) vs *bound parameter* (safe),
so at a query sink only the QUERY-string argument is inspected — a value passed to bind_param never flags.
A query built with prepare()+placeholders is SAFE even if a bound value is user input. Domain of
applicability: single-function / straight-line PHP using mysqli / PDO / pg.
"""
import re
import sys

_SOURCES = [
    r"\$_GET\b", r"\$_POST\b", r"\$_REQUEST\b", r"\$_COOKIE\b", r"\$_SERVER\b",
    r"php://input", r"getenv\s*\(",
]
_SOURCE_RE = re.compile("|".join(_SOURCES))
# query sinks (arg with the query string). mysqli_query($conn, Q) -> Q is arg1; $x->query(Q) -> arg0.
_SINK_FUNC = re.compile(r"\b(mysqli_query|mysql_query|pg_query)\s*\(")
_SINK_METH = re.compile(r"->\s*(query|exec|multi_query|unbuffered_query)\s*\(")
_PREPARE = re.compile(r"->\s*prepare\s*\(")
_ASSIGN = re.compile(r"^\s*(\$\w+)\s*=\s*(.+?);?\s*$")
_DQ_STR = re.compile(r'"(?:[^"\\]|\\.)*"')   # double-quoted (interpolating) string
_SQ_STR = re.compile(r"'(?:[^'\\]|\\.)*'")   # single-quoted (non-interpolating) string
_VAR = re.compile(r"\$\w+")


def _interp_vars(dq_string):
    """Variables interpolated inside a double-quoted PHP string."""
    return set(_VAR.findall(dq_string))


def _expr_tainted(expr, tainted):
    """Is this PHP expression user-controlled? An inline SOURCE, a reference to a tainted $var, OR a
    double-quoted string that INTERPOLATES a source/tainted var. Single-quoted strings never interpolate."""
    # 1. double-quoted (interpolating) strings FIRST — inline SOURCE or interpolated tainted/source var.
    #    (Do this before touching single quotes, which may be literal SQL chars INSIDE a "..." string.)
    for dq in _DQ_STR.findall(expr):
        if _SOURCE_RE.search(dq):
            return True
        for v in _interp_vars(dq):
            if v in tainted:
                return True
    # 2. outside string literals: blank ALL strings, then check for a source or a tainted-var reference
    outside = _SQ_STR.sub("''", _DQ_STR.sub('""', expr))
    if _SOURCE_RE.search(outside):
        return True
    for v in set(_VAR.findall(outside)):
        if v in tainted:
            return True
    return False


def analyze(code):
    lines = code.split("\n")
    assigns = []
    for ln in lines:
        m = _ASSIGN.match(ln)
        if m and not m.group(2).lstrip().startswith("="):
            assigns.append((m.group(1), m.group(2)))
    tainted = set()
    changed = True
    while changed:
        changed = False
        for lhs, rhs in assigns:
            if lhs in tainted:
                continue
            # a var assigned from ->prepare(...) is a statement handle, NOT a tainted query string
            if _PREPARE.search(rhs):
                continue
            if _expr_tainted(rhs, tainted):
                tainted.add(lhs); changed = True
    for ln in lines:
        # a prepared statement's query arg: if prepare() gets a tainted string it is STILL injection
        pm = _PREPARE.search(ln)
        if pm:
            qarg = _first_arg(ln[pm.end():])
            if _expr_tainted(qarg, tainted):
                return {"verdict": "FLAG", "why": "user input in a prepared-statement query string: %s" % qarg.strip()[:70]}
            continue  # a constant/parameterised prepare() is the SAFE channel
        fm = _SINK_FUNC.search(ln)
        if fm:
            args = _split_args(ln[fm.end():])
            qarg = args[1] if len(args) > 1 else (args[0] if args else "")  # mysqli_query(conn, Q)
            if _expr_tainted(qarg, tainted):
                return {"verdict": "FLAG", "why": "user input reaches a SQL query sink: %s" % qarg.strip()[:70]}
        mm = _SINK_METH.search(ln)
        if mm:
            qarg = _first_arg(ln[mm.end():])
            if _expr_tainted(qarg, tainted):
                return {"verdict": "FLAG", "why": "user input reaches a SQL query method: %s" % qarg.strip()[:70]}
    return {"verdict": "SAFE", "why": "query string constant/parameterised; user input (if any) is a bound parameter"}


def _split_args(rest):
    args, depth, cur, instr, strch = [], 1, "", False, ""
    for ch in rest:
        if instr:
            cur += ch
            if ch == strch:
                instr = False
            continue
        if ch in "\"'":
            instr, strch = True, ch; cur += ch
        elif ch in "([{":
            depth += 1; cur += ch
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                args.append(cur); break
            cur += ch
        elif ch == "," and depth == 1:
            args.append(cur); cur = ""
        else:
            cur += ch
    return [a.strip() for a in args]


def _first_arg(rest):
    a = _split_args(rest)
    return a[0] if a else ""


def verdict(code):
    return analyze(code)["verdict"]


def _run_probes(path):
    import json
    probes = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    flags = [p for p in probes if p["expected_verdict"] == "FLAG"]
    safes = [p for p in probes if p["expected_verdict"] == "SAFE"]
    missed, false_pos = [], []
    for p in probes:
        got = verdict(p["code"])
        ok = got == p["expected_verdict"]
        if not ok and p["expected_verdict"] == "FLAG":
            missed.append(p)
        if not ok and p["expected_verdict"] == "SAFE":
            false_pos.append(p)
        print("  %-4s expected=%-4s %s  %s" % (got, p["expected_verdict"], "OK" if ok else "FAIL", p.get("note", "")))
    recall = 1.0 if not flags else 1.0 - len(missed) / len(flags)
    print("\nprobes=%d (FLAG=%d, SAFE=%d) | recall=%.3f | false_positives=%d" % (len(probes), len(flags), len(safes), recall, len(false_pos)))
    ok = recall == 1.0 and not false_pos and flags and safes
    print("RESULT: %s" % ("PROVEN (recall=1.0, FP0, non-degenerate)" if ok else "NOT PROVEN"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(_run_probes(sys.argv[1] if len(sys.argv) > 1 else "probes/probes.jsonl"))
