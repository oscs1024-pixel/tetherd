#!/usr/bin/env bash
set -euo pipefail

bad="$(
  grep -R -n -E '^[[:space:]]*-[[:space:]]*uses:[[:space:]]+' .github/workflows --include='*.yml' --include='*.yaml'     | grep -E -v '@[0-9a-f]{40}([[:space:]]+#.*)?$' || true
)"

if [[ -n "$bad" ]]; then
  echo "GitHub Actions must be pinned to immutable 40-character commit SHAs:" >&2
  echo "$bad" >&2
  exit 1
fi
