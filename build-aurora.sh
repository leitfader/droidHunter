#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAVA_HOME="${JAVA_HOME:-}"

if [ -z "$JAVA_HOME" ]; then
  for candidate in \
    /usr/lib/jvm/java-21-openjdk-amd64 \
    /usr/lib/jvm/java-21-openjdk \
    /usr/lib/jvm/jdk-21 \
    /usr/lib/jvm/jdk-21* \
    /usr/lib/jvm/java-17-openjdk-amd64 \
    /usr/lib/jvm/java-17-openjdk \
    /usr/lib/jvm/jdk-17 \
    /usr/lib/jvm/jdk-17* \
    /Library/Java/JavaVirtualMachines/*/Contents/Home; do
    if [ -x "$candidate/bin/java" ]; then
      JAVA_HOME="$candidate"
      break
    fi
  done
fi

if [ -z "$JAVA_HOME" ] || [ ! -x "$JAVA_HOME/bin/java" ]; then
  echo "JDK 21+ required. Install OpenJDK 21 and set JAVA_HOME." >&2
  exit 1
fi

JAVA_VERSION="$("$JAVA_HOME/bin/java" -version 2>&1 | head -n 1)"
JAVA_MAJOR="$(echo "$JAVA_VERSION" | sed -E 's/.*version "([0-9]+).*/\1/')"

if [ -z "$JAVA_MAJOR" ] || [ "$JAVA_MAJOR" -lt 21 ]; then
  echo "JDK 21+ required. Found: $JAVA_VERSION" >&2
  exit 1
fi

export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"

if ! command -v gradle >/dev/null 2>&1; then
  echo "Gradle not found. Install Gradle or add it to PATH." >&2
  exit 1
fi

gradle -p "$ROOT_DIR/aurora-downloader" installDist
