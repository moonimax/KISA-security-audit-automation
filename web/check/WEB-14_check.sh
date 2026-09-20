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

check_perm_le() {
    local f="$1" max="$2"
    local perm
    perm="$(stat -c '%a' "$f" 2>/dev/null)"
    [ -z "$perm" ] && return 2
    [ "$perm" -le "$max" ] && return 0
    return 1
}

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
            if [ -z "$perm" ]; then fail="true"; detail="${detail}Apache(${main}) 권한 조회 실패. "
            elif webdetect_perm_exceeds "$perm" 750; then vuln="true"; detail="${detail}Apache(${main}) 권한 ${perm} 초과. "
            else detail="${detail}Apache(${main}) 권한 ${perm} 양호. "; fi
        fi
    fi

    if webdetect_nginx_present; then
        local nmain; nmain="$(webdetect_nginx_mainconf 2>/dev/null)"
        if [ -n "$nmain" ]; then
            local perm; perm="$(stat -c '%a' "$nmain" 2>/dev/null)"
            if [ -z "$perm" ]; then fail="true"; detail="${detail}Nginx(${nmain}) 권한 조회 실패. "
            elif webdetect_perm_exceeds "$perm" 750; then vuln="true"; detail="${detail}Nginx(${nmain}) 권한 ${perm} 초과. "
            else detail="${detail}Nginx(${nmain}) 권한 ${perm} 양호. "; fi
        fi
    fi

    if webdetect_tomcat_present; then
        local wxml; wxml="$(webdetect_tomcat_web_xml 2>/dev/null)"
        if [ -n "$wxml" ]; then
            local perm; perm="$(stat -c '%a' "$wxml" 2>/dev/null)"
            if [ -z "$perm" ]; then fail="true"; detail="${detail}Tomcat(${wxml}) 권한 조회 실패. "
            elif webdetect_perm_exceeds "$perm" 750; then vuln="true"; detail="${detail}Tomcat(${wxml}) 권한 ${perm} 초과. "
            else detail="${detail}Tomcat(${wxml}) 권한 ${perm} 양호. "; fi
        fi
    fi

    CHECK_DETAIL="${detail% }"
    if [ -z "$CHECK_DETAIL" ]; then
        CHECK_DETAIL="설치된 서비스의 주 설정 파일을 찾지 못함."
        return "$KISA_EXIT_FAIL"
    fi
    [ "$vuln" = "true" ] && return "$KISA_EXIT_VULN"
    [ "$fail" = "true" ] && return "$KISA_EXIT_FAIL"
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
