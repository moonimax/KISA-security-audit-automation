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
FIX_DETAIL=""

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

do_fix() {
    do_check
    local current=$?

    if [ "$current" -eq "$KISA_EXIT_GOOD" ]; then
        FIX_DETAIL="현재 버전이 최소 요구 버전을 충족함. 조치가 필요하지 않음."
        return "$KISA_EXIT_GOOD"
    fi
    if [ "$current" -eq "$KISA_EXIT_ERROR" ]; then
        FIX_DETAIL="버전 확인 실패로 조치 대상 상태를 판단할 수 없음."
        return "$KISA_EXIT_ERROR"
    fi

    FIX_DETAIL="현재 버전이 최소 요구 버전(${MIN_SAFE_VERSION}) 미만입니다. 서비스 중단 위험으로 자동 업그레이드는 수행하지 않습니다. 점검창을 통해 'apt-get update && apt-get install --only-upgrade mysql-server' 등으로 수동 패치하세요. (${CHECK_DETAIL})"
    return "$KISA_EXIT_MANUAL"
}

do_fix
KISA_FIX_RC=$?
log_info "D-25 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
