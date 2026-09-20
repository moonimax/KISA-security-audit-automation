#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-25"
readonly ITEM_TITLE="주기적 보안 패치 및 벤더 권고사항 적용"
readonly ACTION_TAG="승인요청"
readonly IMPACT="패치 적용은 유지보수 일정과 회귀 테스트가 필요해 무중단 자동화 대상이 아님"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

apache_version_string() {
    local ctl
    ctl="$(webdetect_apache_ctl 2>/dev/null)" || return 1
    "$ctl" -v 2>/dev/null | head -n1
}
nginx_version_string() {
    command -v nginx >/dev/null 2>&1 || return 1
    nginx -v 2>&1 | head -n1
}

do_check() {
    if ! webdetect_apache_present && ! webdetect_nginx_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    local detail="" outdated="false" version major maj min
    if webdetect_apache_present; then
        version="$(apache_version_string)"
        detail="${detail}Apache: ${version}. "
        major="$(printf '%s' "$version" | grep -oE 'Apache/[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+' | head -n1)"
        if [ -n "$major" ]; then
            maj="${major%%.*}"; min="${major#*.}"
            { [ "$maj" -lt 2 ] || { [ "$maj" -eq 2 ] && [ "$min" -lt 4 ]; }; } && outdated="true"
        fi
    fi
    if webdetect_nginx_present; then
        version="$(nginx_version_string)"
        detail="${detail}Nginx: ${version}. "
        major="$(printf '%s' "$version" | grep -oE 'nginx/[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+' | head -n1)"
        if [ -n "$major" ]; then
            maj="${major%%.*}"; min="${major#*.}"
            { [ "$maj" -lt 1 ] || { [ "$maj" -eq 1 ] && [ "$min" -lt 20 ]; }; } && outdated="true"
        fi
    fi
    if [ "$outdated" = "true" ]; then
        CHECK_DETAIL="${detail% } - 지원 기준보다 오래된 버전."
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="${detail% } - 지원되는 보안 패치 기준 충족."
    return "$KISA_EXIT_GOOD"
}

do_fix() {
    do_check
    local current=$?

    if [ "$current" -eq "$KISA_EXIT_GOOD" ]; then
        FIX_DETAIL="이미 양호 상태로 조치가 필요하지 않음."
        return 0
    fi
    if [ "$current" -eq "$KISA_EXIT_FAIL" ]; then
        FIX_DETAIL="조치 대상 상태를 확인할 수 없어 조치를 수행하지 않음."
        return 2
    fi

    if ! is_approved; then
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 패치 적용은 유지보수 일정과 회귀 테스트가 필요함. 승인 후 재실행해도 자동 패치는 수행되지 않으며 버전 정보만 재확인됨."
        return 1
    fi

    FIX_DETAIL="보안 패치 자동 적용은 서비스 중단 위험이 있어 수행하지 않음. 패키지 관리자(apt 등)로 Apache/Nginx 최신 보안 패치를 확인하고, 유지보수 시간에 테스트 후 적용해야 함. 시스템 변경 없이 안내만 반환함."
    return 1
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-25 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
