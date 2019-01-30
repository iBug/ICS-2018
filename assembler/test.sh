#!/bin/bash

PYTHON=python3
PYPROG=assemble.py
LC3AS=lc3as
TESTDIR=test

fail() {
  echo "$*" >&2
  exit 1
}

test_single() {
  local e
  NAME="$1"
  [[ "${NAME:${#NAME}-4}" = ".asm" ]] && NAME="${NAME:0:${#NAME}-4}"

  echo "[$NAME.asm] TEST START"

  # Create reference object file
  "$LC3AS" "$NAME" >/dev/null
  rm "$NAME.sym"
  mv "$NAME.obj" "$NAME.o"

  # Call the assembler
  "$PYTHON" "$PYPROG" "$NAME" >/dev/null
  e=$?
  (( e )) && fail "$PYPROG exited with code $e"

  # Compare results
  cmp "$NAME.obj" "$NAME.o"
  e=$?
  (( e )) && fail "Output file is wrong"

  # Cleanup
  rm "$NAME".{o,obj,sym}
  echo "[$NAME.asm] TEST PASSED"
}

for file in $TESTDIR/*.asm; do
  test_single "$file"
done
