#!/bin/env bash

AFLCC=afl-clang-fast
AFLCXX=afl-clang-fast++
FLAGS=
export CFLAGS=$FLAGS
export CXXFLAGS=$FLAGS

$AFLCC -Wall -Weverything \
  ./*.c \
  -fsanitize=fuzzer $FLAGS \
  -o ./harness

