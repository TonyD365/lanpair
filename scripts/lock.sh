#!/bin/sh
# Regenerate the hash-pinned requirement files used by CI (needs uv).
set -eu
cd "$(dirname "$0")/../requirements"
for name in dev audit release; do
  uv pip compile --quiet --universal --python-version 3.10 --generate-hashes "$name.in" -o "$name.txt"
done
uv pip compile --quiet --universal --python-version 3.12 --generate-hashes fuzz.in -o fuzz.txt
