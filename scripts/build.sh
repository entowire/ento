#!/usr/bin/env bash
# Builds static ento binaries into dist/. Reproducible: no cgo, trimmed paths, no build IDs.
# Windows builds are packaged as ento-windows-<arch>.zip: ento.exe, ento-tray.exe (the person's
# sign-in in the notification area, a GUI program), the pinned, verified wintun.dll for that
# architecture (scripts/wintun.env) and Wintun's licence, with fixed timestamps.
#
# Usage: scripts/build.sh [GOOS/GOARCH ...]   (default: linux/amd64)
#        scripts/build.sh linux/amd64 linux/arm64 darwin/arm64 windows/amd64
set -euo pipefail

cd "$(dirname "$0")/.."
# Releases are tagged ento-vX.Y.Z; anything else builds as a development version.
version="$(git describe --tags --match 'ento-v*' --dirty 2>/dev/null | sed 's/^ento-v//' || true)"
version="${version:-dev-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
targets=("${@:-linux/amd64}")
mkdir -p dist

wintun() { # wintun <arch>: path of the verified wintun.dll for arch, downloaded once
  # shellcheck source=wintun.env
  . scripts/wintun.env
  local cache="dist/.wintun-$WINTUN_VERSION"
  if [[ ! -d "$cache" ]]; then
    local zip="dist/.wintun.zip"
    curl -fsSL -o "$zip" "$WINTUN_URL"
    echo "$WINTUN_SHA256  $zip" | sha256sum -c --quiet - || { echo "wintun: checksum mismatch" >&2; exit 1; }
    mkdir -p "$cache" && python3 -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$zip" "$cache"
    rm "$zip"
  fi
  echo "$cache/wintun"
}

for t in "${targets[@]}"; do
  os="${t%/*}"; arch="${t#*/}"
  exe=""; [[ "$os" == windows ]] && exe=".exe"
  bin="dist/ento-$os-$arch$exe"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false \
    -ldflags "-s -w -buildid= -X main.version=$version" -o "$bin" ./cmd/ento
  out="$bin"
  if [[ "$os" == windows ]]; then
    out="dist/ento-windows-$arch.zip"
    tray="dist/ento-tray-windows-$arch.exe"
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false \
      -ldflags "-s -w -buildid= -H=windowsgui -X main.version=$version" -o "$tray" ./cmd/ento-tray
    w="$(wintun "$arch")"
    python3 - "$out" "$bin" "$tray" "$w/bin/$arch/wintun.dll" "$w/LICENSE.txt" <<'PY'
import sys, zipfile
out, exe, tray, dll, lic = sys.argv[1:]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for src, name in ((exe, "ento.exe"), (tray, "ento-tray.exe"), (dll, "wintun.dll"), (lic, "wintun-LICENSE.txt")):
        info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
        info.external_attr = 0o644 << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(info, open(src, "rb").read())
PY
  fi
  (cd dist && sha256sum "$(basename "$out")" > "$(basename "$out").sha256")
  echo "$out ($version)"
done
