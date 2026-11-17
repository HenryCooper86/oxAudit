#!/bin/sh
# Fail when a Linux binary needs a newer glibc than the release promises.
#
#   tools/check-glibc-floor.sh <binary> <highest allowed glibc version>
#
# The Linux release binaries are built on an old enough system that they run
# on Debian 12, Ubuntu 22.04 and RHEL 9. Moving the build to a newer runner
# raises the requirement without any test noticing: the binary still runs
# where it was built. This reads the versioned glibc symbols the binary
# imports and compares the highest against the allowed one.
set -eu

binary="${1:?usage: check-glibc-floor.sh <binary> <highest allowed glibc version>}"
allowed="${2:?usage: check-glibc-floor.sh <binary> <highest allowed glibc version>}"

symbols="$(objdump -T "$binary")" || {
  echo "cannot read dynamic symbols of $binary" >&2
  exit 2
}
needed="$(printf '%s\n' "$symbols" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/^GLIBC_//' | sort -V | tail -1)"
if [ -z "$needed" ]; then
  echo "$binary imports no versioned glibc symbols; nothing to check" >&2
  exit 2
fi
highest="$(printf '%s\n%s\n' "$allowed" "$needed" | sort -V | tail -1)"
if [ "$highest" != "$allowed" ]; then
  echo "$binary needs glibc $needed, newer than the allowed $allowed." >&2
  echo "Build it on a system whose glibc is $allowed or older." >&2
  exit 1
fi
echo "$binary needs glibc $needed (allowed up to $allowed)"
