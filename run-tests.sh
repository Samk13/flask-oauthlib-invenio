#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

# Use the active Python environment; override PYTHON for a local virtualenv.
# Preserve pytest's configured checks and propagate failures to CI.
"${PYTHON:-python3}" -m pytest "$@"
