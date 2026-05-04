#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Copyright (c) 2025 Red Hat, Inc.
#
# Author: Oliver Steffen <osteffen@redhat.com>
set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

# Fail the test after this timeout
TIMEOUT=180s

echo "================================================================================"
timeout $TIMEOUT "$SCRIPT_DIR/test-in-svsm.sh" --nocc "$@" </dev/null 2>&1
RES=$?
echo "================================================================================"

case $RES in
0)
  echo "Test Pass!"
  exit 0
  ;;
1)
  echo "Test failed"
  exit 1
  ;;
124)
  echo "Test failed: timeout"
  exit 1
  ;;
*)
  echo "Test failed: Unknown error"
  exit 1
  ;;
esac
