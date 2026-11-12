#!/bin/env bash

afl-fuzz -i ./input \
  -o out2 \
  ./harness @@

