#!/usr/bin/env bash
# Copyright (c) 2026 AutoMint. License: see LICENSE.
set -euo pipefail
project="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
: "${MINTAUTH_JAVA_8_HOME:?Set the Java 8 JDK path}"
: "${MINTAUTH_JAVA_21_HOME:?Set the Java 21 JDK path}"
: "${MINTAUTH_JAVA_25_HOME:?Set the Java 25 JDK path}"
: "${MINTAUTH_GRADLE_9_2_HOME:?Set the Gradle 9.2.0 installation path}"
: "${MINTAUTH_GRADLE_9_8_HOME:?Set the Gradle 9.8.2 installation path}"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$project/.tools/gradle-cache}"
paths="$MINTAUTH_JAVA_8_HOME,$MINTAUTH_JAVA_21_HOME,$MINTAUTH_JAVA_25_HOME"
for target in core forge-1.8.9 fabric-1.21.11 fabric-26.3; do
  directory="$project/$target"; java_home="$MINTAUTH_JAVA_25_HOME"; gradle="$MINTAUTH_GRADLE_9_8_HOME/bin/gradle"; task=build
  if [[ "$target" == core ]]; then directory="$project"; task=core:test; fi
  if [[ "$target" == core || "$target" == forge-1.8.9 ]]; then java_home="$MINTAUTH_JAVA_21_HOME"; gradle="$MINTAUTH_GRADLE_9_2_HOME/bin/gradle"; fi
  (cd -- "$directory"; JAVA_HOME="$java_home" "$gradle" --no-daemon --dependency-verification=strict "-Dorg.gradle.java.installations.paths=$paths" "$task")
  if [[ "$target" != core ]]; then
    before="$(find "$directory/build/libs" -maxdepth 1 -name '*.jar' ! -name '*-thin.jar' ! -name '*-bundled.jar' ! -name '*-sources.jar' ! -name '*-dev.jar' -exec sha256sum {} \;)"
    [[ "$(printf '%s\n' "$before" | wc -l)" == 1 && -n "$before" ]]
    (cd -- "$directory"; JAVA_HOME="$java_home" "$gradle" --no-daemon --dependency-verification=strict "-Dorg.gradle.java.installations.paths=$paths" --rerun-tasks "$task")
    after="$(find "$directory/build/libs" -maxdepth 1 -name '*.jar' ! -name '*-thin.jar' ! -name '*-bundled.jar' ! -name '*-sources.jar' ! -name '*-dev.jar' -exec sha256sum {} \;)"
    [[ "$before" == "$after" ]] || { echo "Non-reproducible $target build" >&2; exit 1; }
  fi
done
python3 "$project/scripts/package-artifacts.py"
