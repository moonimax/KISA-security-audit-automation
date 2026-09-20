#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/mysql_lib.sh"

readonly ITEM_CODE="D-25"
readonly ITEM_TITLE="주기적 보안 패치 및 벤더 권고 사항 적용"
readonly ACTION_TAG="승인요청"
readonly IMPACT="기존 시스템 운영 등에 사용되던 시스템 구성 요소와 호환성 문제가 발생할 수 있음"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    local version
    version="$(mysql_exec "SELECT VERSION();" | sed -E 's/-.*$//')"
    if [ -z "$version" ]; then
        CHECK_DETAIL="버전 확인 실패"
        return "$KISA_EXIT_ERROR"
    fi

    if [ "$(printf '%s\n%s\n' "$MIN_SAFE_VERSION" "$version" | sort -V | head -1)" = "$MIN_SAFE_VERSION" ]; then
        CHECK_DETAIL="현재 버전: $version (최소 요구: $MIN_SAFE_VERSION)"
        return "$KISA_EXIT_GOOD"
    fi

    CHECK_DETAIL="현재 버전: $version (최소 요구: $MIN_SAFE_VERSION 미만)"
    return "$KISA_EXIT_VULN"
}

verify_and_get_status do_check

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
