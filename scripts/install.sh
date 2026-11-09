#!/usr/bin/env sh
# Add slsec shift-left security hooks to the current git repo.
#
#   sh install.sh                          # auto-detect profiles, warn mode
#   sh install.sh --profile terraform,docker --mode block
#
# Environment overrides: SLSEC_SOURCE_URL (git URL of this repo), SLSEC_REV (tag).
# Prefers uv, then pipx, then pip --user. Never pipes remote scripts into a shell.
set -eu

SLSEC_SOURCE_URL="${SLSEC_SOURCE_URL:-https://github.com/kston83/shift-left-security}"
SLSEC_REV="${SLSEC_REV:-v0.2.0}"
SPEC="git+${SLSEC_SOURCE_URL}@${SLSEC_REV}"

if ! git rev-parse --show-toplevel >/dev/null 2>&1; then
  echo "slsec: run this from inside a git repository" >&2
  exit 2
fi

if command -v uv >/dev/null 2>&1; then
  command -v pre-commit >/dev/null 2>&1 || uv tool install pre-commit
  uvx --from "$SPEC" slsec init --source-url "$SLSEC_SOURCE_URL" --rev "$SLSEC_REV" "$@"
elif command -v pipx >/dev/null 2>&1; then
  command -v pre-commit >/dev/null 2>&1 || pipx install pre-commit
  pipx run --spec "$SPEC" slsec init --source-url "$SLSEC_SOURCE_URL" --rev "$SLSEC_REV" "$@"
else
  PY="$(command -v python3 || command -v python || true)"
  if [ -z "$PY" ]; then
    echo "slsec: need Python 3.9+ (or uv / pipx) on PATH" >&2
    exit 2
  fi
  "$PY" -m pip install --user --quiet --disable-pip-version-check pre-commit "$SPEC"
  "$PY" -m slsec init --source-url "$SLSEC_SOURCE_URL" --rev "$SLSEC_REV" "$@"
fi
