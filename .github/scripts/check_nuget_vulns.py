#!/usr/bin/env python3
"""Gate on vulnerable NuGet packages, deterministically.

WHY THIS EXISTS RATHER THAN A GREP
`dotnet list package --vulnerable` EXITS 0 EVEN WHEN IT FINDS SOMETHING
(verified 2026-08-11 against a deliberately vulnerable project), so the exit
code cannot be the gate. The obvious fallback -- grepping the human-readable
table for '>' -- is fragile in exactly the way that matters: it fails OPEN. A
column change, a localised runner, or an empty result all produce "no match",
which reads identically to "nothing vulnerable".

So this parses `--format json` instead, and refuses to interpret a document it
does not recognise.

SELF-TEST
Run with --selftest. It feeds the parser fixtures whose answers are known and
asserts it both FAILS on a vulnerable document and PASSES on a clean one. A
detector that cannot be shown to fail is not evidence of anything, and CI runs
this immediately before the real check for that reason.

Usage:
    dotnet list package --vulnerable --include-transitive --format json \\
      | python check_nuget_vulns.py
    python check_nuget_vulns.py --selftest

Exit codes: 0 nothing at or above the threshold, 1 findings, 2 unusable input.
"""
import json
import sys

# Matches the npm gate in the same workflow. Low and moderate advisories against
# untouched transitive dependencies would otherwise block every PR with no
# defect in this repo; they are reported, not enforced.
BLOCKING = {"high", "critical"}

# The only schema this parser has been verified against. A future SDK bumping
# this is a reason to STOP, not to assume the shape still holds -- silently
# finding nothing in a document we cannot read is the failure mode this whole
# file exists to avoid.
SUPPORTED_VERSION = 1


def findings(doc):
    """Every vulnerability in the document, with where it came from."""
    if not isinstance(doc, dict):
        raise ValueError("top level is not an object")
    version = doc.get("version")
    if version != SUPPORTED_VERSION:
        raise ValueError(
            f"unsupported schema version {version!r} (expected {SUPPORTED_VERSION}); "
            "the output format changed -- re-verify this parser before trusting it"
        )
    if "projects" not in doc:
        raise ValueError("no 'projects' key")

    out = []
    for project in doc.get("projects") or []:
        path = project.get("path", "<unknown project>")
        # A clean project has no 'frameworks' key at all -- that is the normal
        # quiet case, not a parse failure.
        for framework in project.get("frameworks") or []:
            fw = framework.get("framework", "?")
            for kind in ("topLevelPackages", "transitivePackages"):
                for pkg in framework.get(kind) or []:
                    for vuln in pkg.get("vulnerabilities") or []:
                        out.append({
                            "project": path,
                            "framework": fw,
                            "package": pkg.get("id", "?"),
                            "version": pkg.get("resolvedVersion", "?"),
                            "severity": (vuln.get("severity") or "?"),
                            "advisory": vuln.get("advisoryurl", ""),
                            "transitive": kind == "transitivePackages",
                        })
    return out


def report(found):
    """Print everything, return the count that should block."""
    blocking = [f for f in found if f["severity"].lower() in BLOCKING]
    if not found:
        print("No vulnerable NuGet packages reported.")
        return 0

    for f in found:
        gate = "BLOCKING" if f["severity"].lower() in BLOCKING else "advisory"
        where = "transitive" if f["transitive"] else "direct"
        print(f"  [{gate}] {f['severity']:<9} {f['package']} {f['version']} "
              f"({where}, {f['framework']}) {f['advisory']}")
        print(f"             in {f['project']}")

    print(f"\n{len(found)} advisory/advisories, {len(blocking)} at or above "
          f"{'/'.join(sorted(BLOCKING))}.")
    return len(blocking)


# --------------------------------------------------------------------- selftest
CLEAN = {
    "version": 1,
    "parameters": "--vulnerable --include-transitive",
    "projects": [{"path": "clean.csproj"}],
}

VULNERABLE = {
    "version": 1,
    "parameters": "--vulnerable --include-transitive",
    "projects": [{
        "path": "bad.csproj",
        "frameworks": [{
            "framework": "net10.0",
            "topLevelPackages": [{
                "id": "Probe.Package",
                "resolvedVersion": "1.0.0",
                "vulnerabilities": [
                    {"severity": "Critical", "advisoryurl": "https://example.invalid/a"},
                ],
            }],
            "transitivePackages": [{
                "id": "Probe.Transitive",
                "resolvedVersion": "2.0.0",
                "vulnerabilities": [
                    {"severity": "Moderate", "advisoryurl": "https://example.invalid/b"},
                ],
            }],
        }],
    }],
}


def selftest():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")
        ok = ok and cond

    # The case that matters most: can this thing fail at all?
    found = findings(VULNERABLE)
    check("detects a vulnerability", len(found) == 2)
    check("blocks on critical", report(found) == 1)
    check("reads transitive packages too",
          any(f["transitive"] for f in found))

    # And does it stay quiet when it should.
    check("clean document yields nothing", findings(CLEAN) == [])

    # A schema it has not been checked against must stop the build, not sail
    # through reporting zero findings.
    for bad, why in ((  {"version": 2, "projects": []}, "future schema version"),
                     (  {"projects": []},              "missing version"),
                     (  {"version": 1},                "missing projects"),
                     (  [],                            "not an object")):
        try:
            findings(bad)
            check(f"rejects {why}", False)
        except ValueError:
            check(f"rejects {why}", True)

    print("\nself-test PASSED" if ok else "\nself-test FAILED")
    return 0 if ok else 1


def main():
    if "--selftest" in sys.argv:
        return selftest()

    raw = sys.stdin.read()
    if not raw.strip():
        print("::error::no input -- `dotnet list package` produced nothing", file=sys.stderr)
        return 2
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"::error::output was not JSON ({e}); refusing to guess", file=sys.stderr)
        print(raw[:2000], file=sys.stderr)
        return 2
    try:
        found = findings(doc)
    except ValueError as e:
        print(f"::error::unrecognised output shape: {e}", file=sys.stderr)
        return 2

    n = report(found)
    if n:
        print(f"::error::{n} NuGet package(s) with {'/'.join(sorted(BLOCKING))} "
              f"severity advisories")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
