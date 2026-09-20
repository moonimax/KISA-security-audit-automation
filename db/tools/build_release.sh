#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    printf 'usage: %s <project-root> <output-dir>\n' "$0" >/dev/stderr
    exit 2
fi

PROJECT_ROOT="$(cd -P -- "$1" && pwd)"
OUTPUT_DIR="$(cd -P -- "$2" && pwd)"
MANIFEST="${OUTPUT_DIR}/.release-manifest"

for required in check fix lib; do
    [ -d "${PROJECT_ROOT}/${required}" ] || {
        printf 'required directory missing: %s\n' "${PROJECT_ROOT}/${required}" >/dev/stderr
        exit 2
    }
done

(
    cd "$PROJECT_ROOT"
    find check fix lib -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
) >"$MANIFEST"

RELEASE_ID="$(sha256sum "$MANIFEST" | awk '{print $1}')"
printf '%s\n' "$RELEASE_ID" >"${OUTPUT_DIR}/.release-id"
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    -czf "${OUTPUT_DIR}/${RELEASE_ID}.tar.gz" \
    -C "$PROJECT_ROOT" check fix lib \
    -C "$OUTPUT_DIR" .release-manifest .release-id
printf '%s\n' "$RELEASE_ID"
