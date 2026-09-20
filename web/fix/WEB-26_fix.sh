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
FIX_DETAIL=""

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
        CHECK_DETAIL="로그 디렉터리를 찾지 못함."
        return "$KISA_EXIT_FAIL"
    fi
    local vuln="false" detail=""
    local d
    while IFS= read -r d; do
        [ -n "$d" ] || continue
        local dperm; dperm="$(stat -c '%a' "$d" 2>/dev/null)"
        webdetect_perm_exceeds "$dperm" 750 && { vuln="true"; detail="${detail}${d} 디렉터리 초과. "; }
        local f
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            local fperm; fperm="$(stat -c '%a' "$f" 2>/dev/null)"
            webdetect_perm_exceeds "$fperm" 640 && { vuln="true"; detail="${detail}${f} 파일 초과. "; }
        done < <(find -L "$d" -maxdepth 1 -type f 2>/dev/null)
    done < <(printf '%s\n' "$dirs")
    CHECK_DETAIL="${detail:-권한 양호}"
    [ "$vuln" = "true" ] && return "$KISA_EXIT_VULN"
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

    local dirs changed=""
    dirs="$(list_log_dirs)"
    local d
    while IFS= read -r d; do
        [ -n "$d" ] || continue
        local dperm; dperm="$(stat -c '%a' "$d" 2>/dev/null)"
        if webdetect_perm_exceeds "$dperm" 750 && chmod 750 "$d" 2>/dev/null; then
            changed="${changed}${d} "
        fi
        local f
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            local fperm; fperm="$(stat -c '%a' "$f" 2>/dev/null)"
            if webdetect_perm_exceeds "$fperm" 640 && chmod 640 "$f" 2>/dev/null; then
                changed="${changed}${f} "
            fi
        done < <(find -L "$d" -maxdepth 1 -type f 2>/dev/null)
    done < <(printf '%s\n' "$dirs")

    if [ -z "$changed" ]; then
        FIX_DETAIL="조치 대상 권한 변경(chmod)에 실패했거나 대상이 없음."
        return 2
    fi
    FIX_DETAIL="다음 로그 디렉터리/파일 권한을 조정함(디렉터리 750, 파일 640): ${changed% }"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-26 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
