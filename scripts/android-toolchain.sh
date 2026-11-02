#!/usr/bin/env bash
# Installs the pinned Android toolchain (scripts/android.env) into $ANDROID_TOOLCHAIN
# (default ~/opt/android): JDK 21, the SDK command-line tools, Gradle, and the SDK platform,
# build tools and NDK. Downloads are checked against their pinned SHA-256; existing parts are kept.
#
# Usage: scripts/android-toolchain.sh
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=android.env
. scripts/android.env
dir="${ANDROID_TOOLCHAIN:-$HOME/opt/android}"
mkdir -p "$dir"

fetch() { # fetch <url> <sha256> <file>
  curl -fsSL -o "$3" "$1"
  echo "$2  $3" | sha256sum -c --quiet - || { echo "checksum mismatch: $1" >&2; rm -f "$3"; exit 1; }
}
unzip_to() { python3 -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$1" "$2"; }

if [[ ! -x "$dir/jdk/bin/java" ]]; then
  fetch "$JDK_URL" "$JDK_SHA256" "$dir/jdk.tar.gz"
  mkdir -p "$dir/jdk" && tar -xzf "$dir/jdk.tar.gz" -C "$dir/jdk" --strip-components=1 && rm "$dir/jdk.tar.gz"
fi
if [[ ! -x "$dir/sdk/cmdline-tools/latest/bin/sdkmanager" ]]; then
  fetch "$CMDLINE_TOOLS_URL" "$CMDLINE_TOOLS_SHA256" "$dir/clt.zip"
  rm -rf "$dir/clt" && unzip_to "$dir/clt.zip" "$dir/clt" && rm "$dir/clt.zip"
  mkdir -p "$dir/sdk/cmdline-tools" && mv "$dir/clt/cmdline-tools" "$dir/sdk/cmdline-tools/latest" && rm -rf "$dir/clt"
  chmod +x "$dir"/sdk/cmdline-tools/latest/bin/*
fi
if [[ ! -x "$dir/gradle-$GRADLE_VERSION/bin/gradle" ]]; then
  fetch "$GRADLE_URL" "$GRADLE_SHA256" "$dir/gradle.zip"
  unzip_to "$dir/gradle.zip" "$dir" && rm "$dir/gradle.zip" && chmod +x "$dir/gradle-$GRADLE_VERSION/bin/gradle"
fi
export JAVA_HOME="$dir/jdk"
yes | "$dir/sdk/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$dir/sdk" --licenses >/dev/null || true
# shellcheck disable=SC2086
"$dir/sdk/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$dir/sdk" $SDK_PACKAGES >/dev/null
echo "Android toolchain in $dir"
