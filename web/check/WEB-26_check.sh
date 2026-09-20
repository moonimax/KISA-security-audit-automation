#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-26"
readonly ITEM_TITLE="로그 디렉터리 및 파일 권한 설정"
readonly ACTION_TAG="자동조치"
readonly IMPACT="로그 디렉터리/파일 권한만 조정하며 일반적인 경우 서비스 영향 없음"
readonly SEVERITY="중"

CHECK_DETAIL=""

list_log_dirs() {
    webdetect_apache_present && for d in /var/log/apache2 /var/log/httpd; do [ -d "$d" ] && printf '%s\n' "$d"; done
    webdetect_nginx_present && [ -d /var/log/nginx ] && printf '%s\n' /var/log/nginx
    if webdetect_tomcat_present; then
        local home; home="$(webdetect_tomcat_home 2>/dev/null)"
        [ -n "$home" ] && [ -d "$home/logs" ] && printf '%s\n' "$home/logs"
    fi
}

do_check() {
    if ! webdetect_any_httpd_present && ! webdetect_tomcat_present; then
        CHECK_DETAIL="Apache/Nginx/Tomcat 이 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    local dirs
    dirs="$(list_log_dirs)"
    if [ -z "$dirs" ]; then
        CHECK_DETAIL="로그 디렉터리를 찾지 못함(대상 서비스가 아직 로그를 생성하지 않았을 수 있음)."
        return "$KISA_EXIT_FAIL"
    fi

    local vuln="false" detail=""
    local d
    while IFS= read -r d; do
        [ -n "$d" ] || continue
        local dperm
        dperm="$(stat -c '%a' "$d" 2>/dev/null)"
        if webdetect_perm_exceeds "$dperm" 750; then
            vuln="true"
            detail="${detail}${d}(디렉터리 권한 ${dperm}>750) "
        fi
        local f
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            local fperm
            fperm="$(stat -c '%a' "$f" 2>/dev/null)"
            if webdetect_perm_exceeds "$fperm" 640; then
                vuln="true"
                detail="${detail}${f}(파일 권한 ${fperm}>640) "
            fi
        done < <(find -L "$d" -maxdepth 1 -type f 2>/dev/null)
    done < <(printf '%s\n' "$dirs")

    if [ "$vuln" = "true" ]; then
        CHECK_DETAIL="${detail% }"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="로그 디렉터리/파일 권한이 기준(디렉터리 750 이하, 파일 640 이하) 이내임: $(printf '%s' "$dirs" | tr '\n' ' ')"
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
