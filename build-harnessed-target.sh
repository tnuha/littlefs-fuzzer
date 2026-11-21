#!/bin/env bash

AFLCC=afl-clang-fast
FLAGS=
export CFLAGS=$FLAGS

$AFLCC -Wall -Wextra \
  ./*.c \
  $FLAGS \
  -o ./harness

