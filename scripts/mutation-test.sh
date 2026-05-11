#!/usr/bin/env bash
set -euo pipefail

if ! command -v go-mutesting >/dev/null 2>&1; then
  cat >&2 <<'EOF'
go-mutesting is required.
Install the avito-tech fork with:
  go install github.com/avito-tech/go-mutesting/cmd/go-mutesting@latest
EOF
  exit 127
fi

if ! go-mutesting --list-mutators | grep -q '^arithmetic/base$'; then
  cat >&2 <<'EOF'
This project expects the avito-tech go-mutesting fork.
Install it with:
  go install github.com/avito-tech/go-mutesting/cmd/go-mutesting@latest
EOF
  exit 2
fi

# Always prove the unmutated tree is green before spending time on mutations.
go test ./...

exec_timeout="${MUTATION_TIMEOUT:-60}"
config="${MUTATION_CONFIG:-.go-mutesting.yml}"
blacklist="${MUTATION_BLACKLIST:-.go-mutesting-blacklist}"
if [[ $# -gt 0 ]]; then
  targets=("$@")
else
  targets=("./v2" "./v3")
fi

for target in "${targets[@]}"; do
  echo "==> mutation testing ${target}"
  go-mutesting --config="${config}" --blacklist="${blacklist}" --exec-timeout="${exec_timeout}" "${target}"
done
