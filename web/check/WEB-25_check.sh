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

    local detail="" definitely_outdated="false"

    if webdetect_apache_present; then
        local av major
        av="$(apache_version_string)"
        major="$(printf '%s' "$av" | grep -oE 'Apache/[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+' | head -n1)"
        detail="${detail}Apache 버전: ${av:-확인불가}. "
        if [ -n "$major" ]; then
            local maj="${major%%.*}" min="${major#*.}"
            if [ "$maj" -lt 2 ] || { [ "$maj" -eq 2 ] && [ "$min" -lt 4 ]; }; then
                definitely_outdated="true"
                detail="${detail}(2.4 미만으로 명백히 구버전) "
            fi
        fi
    fi

    if webdetect_nginx_present; then
        local nv major
        nv="$(nginx_version_string)"
        major="$(printf '%s' "$nv" | grep -oE 'nginx/[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+' | head -n1)"
        detail="${detail}Nginx 버전: ${nv:-확인불가}. "
        if [ -n "$major" ]; then
            local maj="${major%%.*}" min="${major#*.}"
            if [ "$maj" -lt 1 ] || { [ "$maj" -eq 1 ] && [ "$min" -lt 20 ]; }; then
                definitely_outdated="true"
                detail="${detail}(1.20 미만으로 명백히 구버전) "
            fi
        fi
    fi

    if [ "$definitely_outdated" = "true" ]; then
        CHECK_DETAIL="${detail% } - 지원 기준보다 명백히 오래된 버전이므로 업데이트 필요."
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="${detail% } - 지원되는 보안 패치 기준(Apache 2.4+, Nginx 1.20+) 충족."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
