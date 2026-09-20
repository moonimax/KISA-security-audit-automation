#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-14"
readonly ITEM_TITLE="웹 서비스 경로 내 파일의 접근 통제"
readonly ACTION_TAG="자동조치"
readonly IMPACT="주 설정 파일 권한만 조정하며 일반적인 경우 서비스 영향 없음"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    if ! webdetect_any_httpd_present && ! webdetect_tomcat_present; then
        CHECK_DETAIL="Apache/Nginx/Tomcat 이 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    local vuln="false" fail="false" detail=""
    if webdetect_apache_present; then
        local main; main="$(webdetect_apache_mainconf 2>/dev/null)"
        if [ -n "$main" ]; then
            local perm; perm="$(stat -c '%a' "$main" 2>/dev/null)"
            [ -z "$perm" ] && fail="true" || { webdetect_perm_exceeds "$perm" 750 && { vuln="true"; detail="${detail}Apache 초과. "; }; }
        fi
    fi
    if webdetect_nginx_present; then
        local nmain; nmain="$(webdetect_nginx_mainconf 2>/dev/null)"
        if [ -n "$nmain" ]; then
            local perm; perm="$(stat -c '%a' "$nmain" 2>/dev/null)"
            [ -z "$perm" ] && fail="true" || { webdetect_perm_exceeds "$perm" 750 && { vuln="true"; detail="${detail}Nginx 초과. "; }; }
        fi
    fi
    if webdetect_tomcat_present; then
        local wxml; wxml="$(webdetect_tomcat_web_xml 2>/dev/null)"
        if [ -n "$wxml" ]; then
            local perm; perm="$(stat -c '%a' "$wxml" 2>/dev/null)"
            [ -z "$perm" ] && fail="true" || { webdetect_perm_exceeds "$perm" 750 && { vuln="true"; detail="${detail}Tomcat 초과. "; }; }
        fi
    fi
    CHECK_DETAIL="${detail:-권한 양호}"
    [ "$vuln" = "true" ] && return "$KISA_EXIT_VULN"
    [ "$fail" = "true" ] && return "$KISA_EXIT_FAIL"
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
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local changed=""
    local main; main="$(webdetect_apache_mainconf 2>/dev/null)"
    if [ -n "$main" ]; then
        local perm; perm="$(stat -c '%a' "$main" 2>/dev/null)"
        if [ -n "$perm" ] && webdetect_perm_exceeds "$perm" 750 && chmod 750 "$main" 2>/dev/null; then
            changed="${changed}${main} "
        fi
    fi
    local nmain; nmain="$(webdetect_nginx_mainconf 2>/dev/null)"
    if [ -n "$nmain" ]; then
        local perm; perm="$(stat -c '%a' "$nmain" 2>/dev/null)"
        if [ -n "$perm" ] && webdetect_perm_exceeds "$perm" 750 && chmod 750 "$nmain" 2>/dev/null; then
            changed="${changed}${nmain} "
        fi
    fi
    local wxml; wxml="$(webdetect_tomcat_web_xml 2>/dev/null)"
    if [ -n "$wxml" ]; then
        local perm; perm="$(stat -c '%a' "$wxml" 2>/dev/null)"
        if [ -n "$perm" ] && webdetect_perm_exceeds "$perm" 750 && chmod 750 "$wxml" 2>/dev/null; then
            changed="${changed}${wxml} "
        fi
    fi

    if [ -z "$changed" ]; then
        FIX_DETAIL="조치 대상 파일에 대한 권한 변경(chmod)에 실패함."
        return 2
    fi
    FIX_DETAIL="다음 주 설정 파일 권한을 750 으로 변경함: ${changed% }"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-14 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
