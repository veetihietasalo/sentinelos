#!/usr/bin/env python3
"""Fail if any workflow job can inherit GitHub Actions' 6-hour default timeout.

WHY THIS EXISTS. On 2026-07-24 two `cargo kani -p kernel` runs occupied a
runner for 5 h 38 min and 5 h 41 min before GitHub's default job timeout
killed them. They never failed — they sat there looking busy. Caps were then
added to every job by hand, but nothing stopped the *next* job from being
added without one, which is exactly how the first gap appeared.

A job with no `timeout-minutes` gets 360 minutes. That is never a deliberate
choice in this repo; it is what you get by forgetting. So: every job declares
a cap, and it must be lower than the default it is there to replace.

Run locally with:

    python3 .github/scripts/check-job-timeouts.py
"""

from __future__ import annotations

import glob
import os
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - CI installs it; this is the local hint
    sys.exit("PyYAML is required: pip install pyyaml")

# GitHub Actions' default job timeout, in minutes. A cap equal to or above this
# buys nothing, so it is treated as missing.
GITHUB_DEFAULT_TIMEOUT_MINUTES = 360


def workflow_files(workflows_dir: str) -> list[str]:
    return sorted(
        glob.glob(os.path.join(workflows_dir, "*.yml"))
        + glob.glob(os.path.join(workflows_dir, "*.yaml"))
    )


def check_workflow(path: str) -> tuple[list[str], list[str], int]:
    """Return (problems, skipped, jobs_checked) for one workflow file."""
    with open(path, encoding="utf-8") as handle:
        return check_workflow_text(os.path.basename(path), handle.read())


def check_workflow_text(name: str, text: str) -> tuple[list[str], list[str], int]:
    """Pure core of [`check_workflow`] — no I/O, so `--selftest` can drive it
    with synthetic workflows instead of trusting a one-off manual check."""
    problems: list[str] = []
    skipped: list[str] = []

    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        # A workflow that does not parse is its own emergency: GitHub cannot run
        # it at all, and every run reports failure with zero jobs. That is
        # precisely how verify.yml was silently dead for a week, so treat it as
        # a hard failure here rather than skipping the file.
        return ([f"{name}: not valid YAML — {exc}"], [], 0)

    jobs = (doc or {}).get("jobs") or {}
    if not isinstance(jobs, dict):
        return ([f"{name}: `jobs:` is not a mapping"], [], 0)

    checked = 0
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            problems.append(f"{name}:{job_id} — job is not a mapping")
            continue

        # A job that calls a reusable workflow (`uses:`) cannot set
        # `timeout-minutes` itself — the cap belongs to the called workflow's
        # own jobs. Skipping is correct, not a loophole: the callee is checked
        # too if it lives in this repo.
        if "uses" in job:
            skipped.append(f"{name}:{job_id} (reusable workflow call)")
            continue

        checked += 1
        timeout = job.get("timeout-minutes")

        if timeout is None:
            problems.append(
                f"{name}:{job_id} — no `timeout-minutes` "
                f"(inherits the {GITHUB_DEFAULT_TIMEOUT_MINUTES}-minute default)"
            )
        elif isinstance(timeout, bool) or not isinstance(timeout, int):
            # Catches quoted values and `${{ ... }}` expressions, which this
            # guard cannot evaluate. If one is ever genuinely needed, decide
            # deliberately and widen this branch then.
            problems.append(
                f"{name}:{job_id} — `timeout-minutes: {timeout!r}` is not a plain integer"
            )
        elif timeout <= 0:
            problems.append(f"{name}:{job_id} — `timeout-minutes: {timeout}` must be positive")
        elif timeout >= GITHUB_DEFAULT_TIMEOUT_MINUTES:
            problems.append(
                f"{name}:{job_id} — `timeout-minutes: {timeout}` is not below the "
                f"{GITHUB_DEFAULT_TIMEOUT_MINUTES}-minute default it exists to replace"
            )

    return (problems, skipped, checked)


def selftest() -> int:
    """Prove the guard actually fails on each thing it claims to catch.

    A guard that only ever passes is indistinguishable from no guard, and that
    is the exact failure mode this whole change exists to prevent — so the
    negative cases are checked, not just the positive one.
    """
    capped = "jobs:\n  a:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n"
    cases: list[tuple[str, str, bool]] = [
        ("a capped job passes", capped, False),
        (
            "a missing cap is caught",
            "jobs:\n  a:\n    runs-on: ubuntu-latest\n",
            True,
        ),
        (
            "a cap at the 6-hour default is caught",
            "jobs:\n  a:\n    runs-on: ubuntu-latest\n    timeout-minutes: 360\n",
            True,
        ),
        (
            "a quoted (non-integer) cap is caught",
            'jobs:\n  a:\n    runs-on: ubuntu-latest\n    timeout-minutes: "5"\n',
            True,
        ),
        (
            "a zero/negative cap is caught",
            "jobs:\n  a:\n    runs-on: ubuntu-latest\n    timeout-minutes: 0\n",
            True,
        ),
        (
            # The verify.yml failure class: an unquoted trailing `::` makes the
            # file unparseable, so GitHub runs zero jobs and reports failure.
            "unparseable YAML is caught",
            "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - name: boom ml::\n",
            True,
        ),
        (
            "one uncapped job among capped ones is still caught",
            capped + "  b:\n    runs-on: ubuntu-latest\n",
            True,
        ),
    ]

    failures = 0
    for label, text, expect_problem in cases:
        problems, _skipped, _checked = check_workflow_text("synthetic.yml", text)
        got_problem = bool(problems)
        if got_problem != expect_problem:
            failures += 1
            print(
                f"  FAIL {label}: expected problem={expect_problem}, got {problems}",
                file=sys.stderr,
            )
        else:
            print(f"  ok   {label}")

    # A reusable-workflow call legitimately cannot carry `timeout-minutes`; it
    # must be skipped rather than flagged, or the guard would be unusable the
    # first time someone factors a workflow out.
    problems, skipped, checked = check_workflow_text(
        "synthetic.yml", "jobs:\n  a:\n    uses: ./.github/workflows/other.yml\n"
    )
    if problems or not skipped or checked != 0:
        failures += 1
        print(
            f"  FAIL reusable-workflow call should be skipped: {problems} {skipped} {checked}",
            file=sys.stderr,
        )
    else:
        print("  ok   a reusable-workflow call is skipped, not flagged")

    if failures:
        print(f"\nSELFTEST FAILED ({failures})", file=sys.stderr)
        return 1
    print("SELFTEST PASSED")
    return 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()

    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    workflows_dir = os.path.join(repo_root, ".github", "workflows")

    files = workflow_files(workflows_dir)
    if not files:
        print(f"No workflow files found under {workflows_dir}", file=sys.stderr)
        return 1

    all_problems: list[str] = []
    all_skipped: list[str] = []
    total_checked = 0

    for path in files:
        problems, skipped, checked = check_workflow(path)
        all_problems.extend(problems)
        all_skipped.extend(skipped)
        total_checked += checked

    for entry in all_skipped:
        print(f"skipped: {entry}")

    if all_problems:
        print(f"\nUNCAPPED JOBS ({len(all_problems)}):", file=sys.stderr)
        for problem in all_problems:
            print(f"  - {problem}", file=sys.stderr)
        print(
            "\nEvery job must declare `timeout-minutes` below "
            f"{GITHUB_DEFAULT_TIMEOUT_MINUTES}. Set it well above the job's observed "
            "runtime so it fires only on a genuine hang.",
            file=sys.stderr,
        )
        return 1

    print(f"ALL JOBS CAPPED — {total_checked} job(s) across {len(files)} workflow file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
