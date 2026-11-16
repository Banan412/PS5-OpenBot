#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
bun_bin="${BUN_BIN:-bun}"
if ! command -v "$bun_bin" >/dev/null 2>&1; then
  printf '%s\n' 'Bun 1.4.3 was not found; install it or set BUN_BIN to its executable.' >&2
  exit 1
fi
if [[ "$("$bun_bin" --version)" != '1.4.3' ]]; then
  printf '%s\n' 'This build requires Bun 1.4.3.' >&2
  exit 1
fi
export TENANT_PACKAGE_DIR="$root/ps5-brand"
cd "$root"
"$bun_bin" install --frozen-lockfile
"$bun_bin" run --filter app build
printf 'Website built at %s\n' "$root/app/dist"
