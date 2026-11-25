#!/usr/bin/env python3
"""Check a release evidence record against a clean candidate checkout."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

BASE = {"functional", "security-review", "code-review"}
REQUIRED = {
    "light": BASE,
    "standard": BASE | {"reliability"},
    "high": BASE | {
        "reliability", "integration", "security-tooling", "recovery",
        "independent-verification",
    },
}
HASH = re.compile(r"[0-9a-f]{64}")
REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
CHECK_STATES = {"pass", "fail", "blocked", "not-run", "na"}


def object_fields(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"duplicate JSON field: {name}")
        result[name] = value
    return result


def invalid_constant(value):
    raise ValueError(f"invalid JSON number: {value}")


def string_field(data, name):
    value = data[name]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")
    return value


def flag(data, name):
    value = data[name]
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def indexed(data, name, key="id"):
    rows = data[name]
    if not isinstance(rows, list):
        raise ValueError(f"{name} must be an array")
    result = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError(f"{name} entries must be objects")
        label = string_field(row, key)
        if label in result:
            raise ValueError(f"duplicate {name} identifier: {label}")
        result[label] = row
    return result


def attachment(item, directory, label, blockers):
    path = Path(string_field(item, "path"))
    expected = string_field(item, "sha256")
    if path.is_absolute() or ".." in path.parts or not HASH.fullmatch(expected):
        raise ValueError(f"{label}: expected a relative path and SHA-256")
    source = (directory / path).resolve()
    if directory not in source.parents:
        raise ValueError(f"{label}: attachment escapes the evidence directory")
    if not source.is_file() or source.stat().st_size == 0:
        blockers.append(f"{label}: evidence file missing or empty")
        return expected
    digest = hashlib.sha256()
    with source.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != expected:
        blockers.append(f"{label}: evidence digest mismatch")
    return expected


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30,
        check=True,
    ).stdout.strip()


def results_digest(data):
    fields = (
        "risk", "candidate", "requirements", "specification", "acceptance",
        "checks", "findings",
    )
    content = {name: data[name] for name in fields}
    encoded = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def assess_checks(data, risk, candidate, directory, blockers):
    checks = indexed(data, "checks")
    required = set(REQUIRED[risk])
    for name, row in checks.items():
        if flag(row, "required"):
            required.add(name)
        status = string_field(row, "status")
        string_field(row, "detail")
        if status not in CHECK_STATES:
            raise ValueError(f"{name}: unknown check status")
        if status == "fail":
            blockers.append(f"{name}: check failed")
        if status == "pass":
            if string_field(row, "candidate") != candidate:
                blockers.append(f"{name}: check was recorded for a different candidate")
            string_field(row, "execution")
            string_field(row, "environment")
            attachment(row["evidence"], directory, name, blockers)

    for name in sorted(required):
        row = checks.get(name)
        if row is None or not row["required"] or row["status"] != "pass":
            blockers.append(f"{name}: requires a passing mandatory check")

    acceptance = indexed(data, "acceptance")
    if not acceptance:
        blockers.append("no acceptance criteria")
    for name, row in acceptance.items():
        string_field(row, "expected")
        linked = row["checks"]
        if not isinstance(linked, list) or not linked or any(
            not isinstance(check, str) for check in linked
        ):
            raise ValueError(f"{name}: expected a nonempty array of check IDs")
        for check in linked:
            if check not in required or checks.get(check, {}).get("status") != "pass":
                blockers.append(f"{name}: missing mandatory passing check {check}")
    return {name for name in required if checks.get(name, {}).get("status") == "pass"}


def assess_findings(data, passed, directory, blockers):
    today = datetime.now(timezone(timedelta(hours=8))).date()
    for name, row in indexed(data, "findings").items():
        for key in ("location", "impact", "owner"):
            string_field(row, key)
        severity = string_field(row, "severity")
        status = string_field(row, "status")
        blocking = flag(row, "blocking")
        if severity not in {"critical", "high", "medium", "low"}:
            raise ValueError(f"{name}: unknown severity")
        if status not in {"open", "resolved", "accepted"}:
            raise ValueError(f"{name}: unknown finding status")
        if status == "resolved":
            if string_field(row, "check") not in passed:
                blockers.append(f"{name}: fix needs a passing mandatory recheck")
            continue
        if blocking or severity in {"critical", "high"} or status == "open":
            blockers.append(f"{name}: unresolved finding")
            continue
        string_field(row, "reviewer")
        expires = string_field(row, "expires")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", expires, flags=re.ASCII):
            raise ValueError(f"{name}: expires must use YYYY-MM-DD")
        if date.fromisoformat(expires) < today:
            blockers.append(f"{name}: exception expired")
        attachment(row["record"], directory, name, blockers)


def assess_approvals(data, candidate, directory, blockers, digest_only):
    requirements = attachment(data["requirements"], directory, "requirements", blockers)
    specification = attachment(data["specification"], directory, "specification", blockers)
    approvals = indexed(data, "approvals", "gate")
    if set(approvals) - {"G1", "G2", "G3"}:
        raise ValueError("unknown approval gate")
    gates = ("G1", "G2") if digest_only else ("G1", "G2", "G3")
    for gate in gates:
        row = approvals.get(gate)
        if row is None:
            blockers.append(f"{gate}: missing approval")
            continue
        string_field(row, "reviewer")
        attachment(row["record"], directory, gate, blockers)
        expected = {"requirements_sha256": requirements}
        if gate in {"G2", "G3"}:
            expected["specification_sha256"] = specification
        if gate == "G3":
            expected.update(candidate=candidate, results_sha256=results_digest(data))
        for field, value in expected.items():
            if string_field(row, field) != value:
                blockers.append(f"{gate}: stale or mismatched {field}")


def assess(data, directory, repo, digest_only):
    blockers = []
    risk = string_field(data, "risk")
    candidate = string_field(data, "candidate")
    if risk not in REQUIRED or not REVISION.fullmatch(candidate):
        raise ValueError("expected a valid risk and full Git commit ID")
    if git(repo, "rev-parse", "--verify", "HEAD^{commit}") != candidate:
        blockers.append("checkout HEAD does not match the candidate")
    if git(repo, "status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none"):
        blockers.append("candidate checkout has uncommitted or untracked changes")

    passed = assess_checks(data, risk, candidate, directory, blockers)
    assess_findings(data, passed, directory, blockers)
    assess_approvals(data, candidate, directory, blockers, digest_only)
    return blockers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--digest", action="store_true", help="check G1/G2 and print digest for G3")
    args = parser.parse_args()
    try:
        with args.manifest.open(encoding="utf-8") as handle:
            data = json.load(handle, object_pairs_hook=object_fields, parse_constant=invalid_constant)
        if not isinstance(data, dict):
            raise ValueError("manifest must be an object")
        blockers = assess(data, args.manifest.resolve().parent, args.repo, args.digest)
    except (KeyError, TypeError, ValueError, OSError, RecursionError, subprocess.SubprocessError) as exc:
        print(f"Invalid input or execution error: {exc}", file=sys.stderr)
        return 2
    if blockers:
        for blocker in blockers:
            print(f"BLOCKED: {blocker}", file=sys.stderr)
        return 1
    if args.digest:
        print(results_digest(data))
    else:
        print("Release evidence record passed structural and version checks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
