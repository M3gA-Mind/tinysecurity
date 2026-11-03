#!/usr/bin/env bash
set -euo pipefail
# Match cargo llvm-cov's workspace test/report directory. show-env otherwise
# defaults to target/ and its native profiles would never reach the report.
native_coverage_directory="${CARGO_LLVM_COV_TARGET_DIR:-$(cargo metadata --locked --no-deps --format-version 1 | jq -r .target_directory)/llvm-cov-target}"
eval "$(cargo llvm-cov show-env --sh)"
export CARGO_LLVM_COV_TARGET_DIR="$native_coverage_directory"
export CARGO_LLVM_COV_BUILD_DIR="$native_coverage_directory"
export LLVM_PROFILE_FILE="$native_coverage_directory/tinysecurity-%p-%28m.profraw"
cargo build --target-dir "$CARGO_LLVM_COV_BUILD_DIR" --locked -p tinysecurity-module --lib --example secret_cipher_native_contract --example device_native_contract --example audit_native_contract --all-features
case "${RUNNER_OS:-$(uname -s)}" in
  Linux) library=libtinysecurity_module.so; executable=secret_cipher_native_contract ;;
  macOS|Darwin) library=libtinysecurity_module.dylib; executable=secret_cipher_native_contract ;;
  Windows|MINGW*|MSYS*) library=tinysecurity_module.dll; executable=secret_cipher_native_contract.exe ;;
  *) echo 'unsupported native cipher coverage platform' >&2; exit 1 ;;
esac
audit_executable=audit_native_contract
device_executable=device_native_contract
if [[ "${RUNNER_OS:-}" == Windows ]]; then device_executable+=.exe; audit_executable+=.exe; fi
build_directory="$CARGO_LLVM_COV_BUILD_DIR"
if [[ "${RUNNER_OS:-}" == Windows ]]; then build_directory="$(cygpath -u "$build_directory")"; fi
module="$build_directory/debug/$library"
verifier="$build_directory/debug/examples/$executable"
device_verifier="$build_directory/debug/examples/$device_executable"
audit_verifier="$build_directory/debug/examples/$audit_executable"
if [[ "${RUNNER_OS:-}" == Windows ]]; then
  # The native loader/audit fixture retains the established restricted namespace.
  module="$(cygpath -u "$TINYSECURITY_AUDIT_TEST_ROOT")/$library"
  cp "$build_directory/debug/$library" "$module"
fi
printf 'Native fixtures: repository working directory\n'
"$verifier" "$module"
"$device_verifier" "$module"
"$audit_verifier" "$module"
"$verifier" "$module" 18
external_cwd="$(mktemp -d)"
trap 'rmdir "$external_cwd"' EXIT
printf 'Native fixtures: external working directory\n'
(cd -- "$external_cwd" && "$verifier" "$module" && "$device_verifier" "$module" && "$audit_verifier" "$module" && "$verifier" "$module" 18)
