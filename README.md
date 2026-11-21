# littlefs fuzzer

Mutational grey-box fuzzing harness for
[littlefs](<https://github.com/littlefs-project/littlefs>),
currently at commit
[6cb4e86540eca0d9ba62500a298385c9d863c8be](<https://github.com/littlefs-project/littlefs/commit/6cb4e86540eca0d9ba62500a298385c9d863c8be>).

## Building

Build the AFL-instrumented target with `make build` (or
`./build-harnessed-target.sh`),
assuming a working `afl-clang-fast` install.
If this isn't present, please follow [AFL++'s install instructions](<https://aflplus.plus/docs/install/>).

## Fuzzing

This can be fine-tuned for other purposes,
with:

```sh
./run-fuzzer.sh
```

The harness uses AFL++'s libFuzzer-compatible driver, a preformatted filesystem
snapshot, and shared-memory persistent test cases. Its maximum useful input
size is 64 KiB. Do not append `@@` to the AFL command: that selects the
driver's file-input fallback and loses the shared-memory fast path.

Each input selects one of two targets:

- A bounded operation stream over directories, files, attributes, garbage
  collection, multiple file handles, remounts, and capacity-pressure writes.
  Successful write/sync/read sequences are checked with a small content oracle
  and a separate shadow model of a reserved file.
- A raw-media target that flips bits in a valid formatted image before mounting
  and traversing it.

Operation-stream inputs occasionally inject one deterministic block-device
read, program, erase, or sync failure, discard RAM state, and require a clean
remount. These failures are expected; an ASan/UBSan report, failed invariant,
or failed recovery mount is triage-worthy.
The default output directory is `out`.

## Triage

Replay and minimize the current AFL++ crashes without modifying its output:

```sh
./triage_cases.py --target ./harness --afl-out out
```

Reports are written to `triage/<UTC timestamp>/`. Open its `README.md` for a
simple, deduplicated bug-report view: each result includes one crashing input
(the minimized input when available) and the target's captured output. Each
case still retains its input copy, three replay logs, JSON record, and (for
stable crashes) an `afl-tmin`-minimized input. Use `--no-minimize` for a quick
first pass. The report replaces local checkout, AFL-output, and report paths
in all copied text artifacts, so the timestamped report directory can be shared
without exposing your machine's directory layout.

