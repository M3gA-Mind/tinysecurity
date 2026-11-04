#!/usr/bin/env bash
# Fail when a Linux module library depends on anything beyond glibc and the loader.
#
# A server host loads the released module with dlopen on a minimal image, so every
# DT_NEEDED entry must be satisfied by the base C runtime. A stray entry such as
# libdbus-1.so.3 makes the loader reject the module on hosts that lack it.
#
# Usage: check-module-needed-libs.sh <path-to-libtinysecurity_module.so>
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <module.so>" >&2
  exit 2
fi
module="$1"
if [[ ! -f "$module" ]]; then
  echo "module library is missing: ${module}" >&2
  exit 1
fi

# Base runtime and dynamic loader names, across x86_64 and aarch64 glibc.
allowed='^(libc\.so\.6|libm\.so\.6|libgcc_s\.so\.1|libdl\.so\.2|libpthread\.so\.0|librt\.so\.1|libutil\.so\.1|ld-linux-x86-64\.so\.2|ld-linux-aarch64\.so\.1)$'

needed="$(readelf -d "$module" | sed -n 's/.*(NEEDED).*Shared library: \[\(.*\)\]/\1/p')"
echo "NEEDED entries of ${module}:"
echo "${needed:-<none>}"

unexpected="$(grep -Ev "$allowed" <<< "$needed" || true)"
if [[ -n "$unexpected" ]]; then
  echo "module links libraries beyond the base C runtime:" >&2
  echo "$unexpected" >&2
  exit 1
fi
