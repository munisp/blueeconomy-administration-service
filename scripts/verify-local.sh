#!/usr/bin/env bash
set -euo pipefail

repository_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repository_root"

if [[ -n "$(gofmt -l cmd internal)" ]]; then
  echo "Go source is not formatted:" >&2
  gofmt -l cmd internal >&2
  exit 1
fi

go test -v ./...
go vet ./...

echo "Central administration service local verification completed successfully."
