#!/usr/bin/env python3
"""Replay, group, and minimize AFL++ crashes/hangs without touching the corpus.

Each source test case is copied into a timestamped result directory before it is
executed.  This makes the report suitable for attaching to a bug report even if
the AFL output directory continues to change while triage is running.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def cases_from(afl_out: Path):
    """Yield AFL crash/hang files, including multi-instance output layouts."""
    for kind in ("crashes", "hangs"):
        for directory in sorted(afl_out.rglob(kind)):
            if not directory.is_dir():
                continue
            for path in sorted(directory.iterdir()):
                if path.is_file() and path.name != "README.txt":
                    yield kind, path


def signature(stderr: str, stdout: str, returncode: int | None, timed_out: bool):
    text = stderr + "\n" + stdout
    if timed_out:
        return "timeout"
    for pattern, label in (
        (r"SUMMARY: AddressSanitizer: ([^\n]+)", "asan"),
        (r"SUMMARY: UndefinedBehaviorSanitizer: ([^\n]+)", "ubsan"),
        (r"runtime error: ([^\n]+)", "ubsan"),
    ):
        match = re.search(pattern, text)
        if match:
            detail = re.sub(r"\s+", " ", match.group(1)).strip()
            frame = re.search(r"\bin ([A-Za-z0-9_]+)", detail)
            return f"{label}:{detail if not frame else detail[:frame.start()].rstrip() + ':' + frame.group(1)}"
    # The first project frame keeps ordinary assertion/crash reports grouped too.
    frame = re.search(r"\bin ([A-Za-z0-9_]+)\+", text)
    if frame:
        return f"failure:{frame.group(1)}"
    return f"exit:{returncode}"


def path_redactor(paths: list[tuple[Path, str]]):
    """Replace local paths so a report directory is safe to share."""
    replacements = sorted(
        ((str(path.resolve()), replacement) for path, replacement in paths),
        key=lambda item: len(item[0]), reverse=True,
    )

    def redact(text: str) -> str:
        for path, replacement in replacements:
            text = re.sub(re.escape(path) + r"(?=$|[\\/])", replacement, text)
        return text

    return redact


def replay(target: Path, testcase: Path, timeout: float, env: dict[str, str], redact):
    started = time.monotonic()
    try:
        completed = subprocess.run(
            [str(target), str(testcase)], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, env=env, check=False,
        )
        timed_out = False
        returncode = completed.returncode
        stdout, stderr = completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as error:
        timed_out = True
        returncode = None
        stdout, stderr = error.stdout or b"", error.stderr or b""
    elapsed_ms = round((time.monotonic() - started) * 1000, 1)
    out_text = stdout.decode("utf-8", "replace")
    err_text = stderr.decode("utf-8", "replace")
    return {
        "returncode": returncode, "timed_out": timed_out, "elapsed_ms": elapsed_ms,
        "signature": redact(signature(err_text, out_text, returncode, timed_out)),
        "stdout": redact(out_text), "stderr": redact(err_text),
    }


def markdown_output(stdout: str, stderr: str) -> str:
    """Render captured target output without letting it escape the report."""
    output = ""
    if stdout:
        output += "stdout:\n" + stdout
    if stderr:
        if output:
            output += "\n"
        output += "stderr:\n" + stderr
    if not output:
        return "_(no output)_"

    # Pick a fence longer than any run of backticks in the target output.
    longest = max((len(run) for run in re.findall(r"`+", output)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{output.rstrip()}\n{fence}"


def write_simple_report(report_dir: Path, records: list[dict], target_name: str) -> None:
    """Write one easily attachable failure example for each signature."""
    grouped = Counter(record["signature"] for record in records)
    representatives: dict[str, dict] = {}
    for record in records:
        representatives.setdefault(record["signature"], record)

    lines = [
        "# AFL++ triage report",
        "",
        f"Cases replayed: {len(records)}",
        f"Unique results: {len(grouped)}",
    ]
    for sig, count in grouped.most_common():
        record = representatives[sig]
        case_dir = report_dir / record["case_dir"]
        minimized = case_dir / "minimized"
        if minimized.is_file():
            testcase = minimized
            stdout_path, stderr_path = case_dir / "minimized.stdout", case_dir / "minimized.stderr"
            label = "Minimized crashing input"
        else:
            testcase = case_dir / "input"
            stdout_path, stderr_path = case_dir / "run-1.stdout", case_dir / "run-1.stderr"
            label = "Crashing input"

        stdout = stdout_path.read_text() if stdout_path.is_file() else ""
        stderr = stderr_path.read_text() if stderr_path.is_file() else ""
        input_path = testcase.relative_to(report_dir).as_posix()
        lines.extend([
            "",
            f"## `{sig}` ({count} case{'s' if count != 1 else ''})",
            "",
            f"{label}: [`{input_path}`]({input_path}) ({testcase.stat().st_size} bytes)",
            "",
            f"Reproduce with a matching build: `./{target_name} {input_path}`",
            "",
            "Output:",
            "",
            markdown_output(stdout, stderr),
        ])
    (report_dir / "README.md").write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="./harness", help="instrumented target binary")
    parser.add_argument("--afl-out", default="out", help="AFL++ output directory")
    parser.add_argument("--output", default="triage", help="parent directory for reports")
    parser.add_argument("--timeout", type=float, default=2.0, help="seconds per replay (default: 2)")
    parser.add_argument("--repeats", type=int, default=3, help="replays per case (default: 3)")
    parser.add_argument("--no-minimize", action="store_true", help="skip afl-tmin")
    args = parser.parse_args()

    target, afl_out = Path(args.target).resolve(), Path(args.afl_out).resolve()
    if not target.is_file() or not os.access(target, os.X_OK):
        parser.error(f"target is not executable: {target}")
    if not afl_out.is_dir():
        parser.error(f"AFL output directory not found: {afl_out}")
    if args.timeout <= 0 or args.repeats <= 0:
        parser.error("--timeout and --repeats must be positive")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_dir = Path(args.output).resolve() / stamp
    report_dir.mkdir(parents=True, exist_ok=False)
    (report_dir / "cases").mkdir()

    # Logs and metadata are copied into the report directory. Remove local
    # checkout and AFL layout paths so that directory can be sent as-is.
    redact = path_redactor([
        (report_dir, "<report>"),
        (afl_out, "<afl-out>"),
        (Path.cwd(), "<workspace>"),
        (target.parent, "<target-dir>"),
    ])

    env = os.environ.copy()
    env.setdefault("ASAN_OPTIONS", "abort_on_error=1:detect_leaks=0")
    symbolizer = shutil.which("llvm-symbolizer")
    if symbolizer:
        env.setdefault("ASAN_SYMBOLIZER_PATH", symbolizer)
    tmin = shutil.which("afl-tmin")
    records = []

    for number, (kind, source) in enumerate(cases_from(afl_out), start=1):
        data = source.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        case_dir = report_dir / "cases" / f"{number:04d}-{kind}-{digest[:12]}"
        case_dir.mkdir()
        testcase = case_dir / "input"
        testcase.write_bytes(data)
        runs = [replay(target, testcase, args.timeout, env, redact) for _ in range(args.repeats)]
        for index, run in enumerate(runs, start=1):
            (case_dir / f"run-{index}.stdout").write_text(run.pop("stdout"))
            (case_dir / f"run-{index}.stderr").write_text(run.pop("stderr"))
        signatures = [run["signature"] for run in runs]
        stable = len(set(signatures)) == 1
        reproducible = stable and signatures[0] != "exit:0"
        if stable:
            result_signature = signatures[0] if reproducible else "not-a-failure"
        else:
            result_signature = "flaky:" + " | ".join(sorted(set(signatures)))
        record = {
            "source": source.name, "kind": kind, "sha256": digest, "bytes": len(data),
            "signature": result_signature,
            "reproducible": reproducible, "runs": runs,
            "case_dir": case_dir.relative_to(report_dir).as_posix(),
        }
        # afl-tmin's -x means any non-zero exit is a crash. Do not minimize
        # flaky cases or hangs: those need separate, semantics-aware handling.
        if reproducible and kind == "crashes" and not args.no_minimize and tmin:
            minimized = case_dir / "minimized"
            command = [tmin, "-x", "-m", "none", "-t", str(int(args.timeout * 1000)),
                       "-i", str(testcase), "-o", str(minimized), "--", str(target), "@@"]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, env=env, check=False)
            (case_dir / "afl-tmin.log").write_text(redact(result.stdout))
            record["afl_tmin_returncode"] = result.returncode
            if result.returncode == 0 and minimized.is_file():
                minimized_run = replay(target, minimized, args.timeout, env, redact)
                (case_dir / "minimized.stdout").write_text(minimized_run.pop("stdout"))
                (case_dir / "minimized.stderr").write_text(minimized_run.pop("stderr"))
                record["minimized_bytes"] = minimized.stat().st_size
                record["minimized_replay"] = minimized_run
        (case_dir / "metadata.json").write_text(json.dumps(record, indent=2) + "\n")
        records.append(record)
        print(f"[{number}] {kind} {len(data)} bytes: {record['signature']}", flush=True)

    grouped = Counter(record["signature"] for record in records)
    manifest = {
        "created_utc": stamp, "target": target.name,
        "timeout_seconds": args.timeout, "repeats": args.repeats, "cases": records,
        "unique_signatures": dict(grouped),
    }
    (report_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    write_simple_report(report_dir, records, target.name)
    print(f"\nReport: {report_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
