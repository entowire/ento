#!/usr/bin/env bash
# Builds the Android app (android/) into dist/ento-android-<version>.apk: the agent as an AAR
# (gomobile bind of ./mobile, gomobile pinned in go.mod), then the app with Gradle.
#
# Signing: none. With ENTO_ANDROID_RELEASE=1 the release APK is built unsigned, and signed afterwards
# with apksigner (scripts/publish-site.sh does, with the keystore in /dev/shm): no build step,
# Gradle plugin or Go module ever runs with the key in its environment (2026-11-03 review, R3).
# Without it, a debug-signed APK is built (for testing only). A key in the environment stops it.
#
# Needs the toolchain of scripts/android-toolchain.sh ($ANDROID_TOOLCHAIN, default ~/opt/android).
# Usage: scripts/build-android.sh
set -euo pipefail
cd "$(dirname "$0")/.."
for k in ENTO_ANDROID_KEYSTORE_B64 ENTO_ANDROID_KEYSTORE_PASSWORD ENTO_RELEASE_SIGNING_KEY ENTO_RELEASE_SIGNING_KEY_P256; do
  [[ -z "${!k:-}" ]] || { echo "$k is in the environment: the build runs without keys (sign afterwards)" >&2; exit 1; }
done
# shellcheck source=android.env
. scripts/android.env
dir="${ANDROID_TOOLCHAIN:-$HOME/opt/android}"
export JAVA_HOME="$dir/jdk" ANDROID_HOME="$dir/sdk" ANDROID_NDK_HOME="$dir/sdk/ndk/$NDK_VERSION"
export PATH="$JAVA_HOME/bin:$PATH:/usr/local/go/bin"

version="$(git describe --tags --match 'ento-v*' --dirty 2>/dev/null | sed 's/^ento-v//' || true)"
version="${version:-dev-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
# versionCode from X.Y.Z (X*10000 + Y*100 + Z); development builds are 1.
code=1
if [[ "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  code=$((BASH_REMATCH[1] * 10000 + BASH_REMATCH[2] * 100 + BASH_REMATCH[3]))
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
chmod 700 "$work"

# The agent library, with the gomobile and gobind versions of go.mod.
mkdir -p android/app/libs
GOBIN="$work/bin" go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
PATH="$work/bin:$PATH" gomobile bind -target=android/arm64,android/amd64 -androidapi 26 \
  -javapkg com.entowire.ento -trimpath -ldflags "-s -w -X entowire.com/ento/mobile.version=$version" \
  -o android/app/libs/ento.aar ./mobile

task=assembleDebug apk=android/app/build/outputs/apk/debug/app-debug.apk
if [[ "${ENTO_ANDROID_RELEASE:-}" == 1 ]]; then
  task=assembleRelease apk=android/app/build/outputs/apk/release/app-release-unsigned.apk
fi
(cd android && ENTO_VERSION="$version" ENTO_VERSION_CODE="$code" \
  "$dir/gradle-$GRADLE_VERSION/bin/gradle" --no-daemon --quiet "$task")

mkdir -p dist
out="dist/ento-android-$version.apk"
cp "$apk" "$out"
"$ANDROID_HOME/build-tools/$BUILD_TOOLS/apksigner" verify --print-certs "$out" | grep -m1 'SHA-256' || true
(cd dist && sha256sum "$(basename "$out")" > "$(basename "$out").sha256")
echo "$out ($version, code $code, $task)"
