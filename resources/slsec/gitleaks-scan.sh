#!/usr/bin/env sh
# Full-history gitleaks scan for CI (used by vars/slsecScan.groovy).
# Uses gitleaks from PATH only if it reports the pinned version (SLSEC_GITLEAKS_VERSION);
# otherwise downloads the pinned release and verifies it against the release checksums
# file. Point SLSEC_GITLEAKS_BASE_URL at an Artifactory "generic remote" to avoid
# reaching GitHub from build agents.
# Exit codes: 0 clean, 1 leaks found, other = could not scan.
set -u

V="${SLSEC_GITLEAKS_VERSION:?}"
GL=""
if command -v gitleaks >/dev/null 2>&1; then
  HAVE="$(gitleaks version 2>/dev/null | head -n 1 | tr -d '[:space:]')"
  HAVE="${HAVE#v}"
  if [ "$HAVE" = "$V" ]; then
    GL=gitleaks
  else
    echo "slsec: gitleaks on PATH reports version '${HAVE:-unknown}', not the pinned $V; using the checksum-verified release instead"
  fi
fi

if [ -z "$GL" ]; then
  D=".slsec-cache/gitleaks-$V"
  if [ ! -x "$D/gitleaks" ]; then
    mkdir -p "$D" || exit 3
    case "$(uname -m)" in
      x86_64|amd64) A=x64 ;;
      aarch64|arm64) A=arm64 ;;
      *) echo "slsec: unsupported architecture $(uname -m)"; exit 3 ;;
    esac
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    F="gitleaks_${V}_${OS}_${A}.tar.gz"
    BASE="${SLSEC_GITLEAKS_BASE_URL:-https://github.com/gitleaks/gitleaks/releases/download}/v${V}"
    curl -fsSL -o "$D/$F" "$BASE/$F" || exit 3
    curl -fsSL -o "$D/checksums.txt" "$BASE/gitleaks_${V}_checksums.txt" || exit 3
    if command -v sha256sum >/dev/null 2>&1; then SUM="sha256sum"; else SUM="shasum -a 256"; fi
    (cd "$D" && grep " $F\$" checksums.txt | $SUM -c -) || { echo "slsec: gitleaks checksum mismatch"; exit 3; }
    tar -xzf "$D/$F" -C "$D" gitleaks || exit 3
  fi
  GL="$D/gitleaks"
fi

if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = "true" ]; then
  echo "slsec: WARNING shallow clone, only the fetched history is scanned (disable shallow clone in the checkout for full coverage)"
fi

"$GL" git . --redact --no-banner --report-format sarif --report-path "${SLSEC_REPORT_DIR:-.}/gitleaks.sarif"
