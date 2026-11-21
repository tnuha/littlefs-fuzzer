#!/usr/bin/env bash
set -eu

afl-fuzz -i ./input \
  -o "out" \
  -G 65536 \
  ./harness

