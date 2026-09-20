#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-07"
readonly ITEM_TITLE="웹 서비스 경로 내 불필요한 파일 제거"
readonly ACTION_TAG="자동조치"
readonly IMPACT="사전 정의된 기본 샘플/매뉴얼 파일만 제거하며 일반적인 경우 서비스 영향 없음"
readonly SEVERITY="중"

CHECK_DETAIL=""
FIX_DETAIL=""

list_known_unnecessary_paths() {
    if webdetect_apache_present; then
        local docroot
        docroot="$(webdetect_apache_docroot)"
        for c in "$docroot/manual" /usr/share/apache2/manual /var/www/manual /var/www/html/manual; do
            [ -e "$c" ] && printf '%s\n' "$c"
        done
    fi
    if webdetect_nginx_present; then
        local ndocroot
        ndocroot="$(webdetect_nginx_docroot)"
        for c in "$ndocroot/index.nginx-debian.html" /usr/share/nginx/html/index.nginx-debian.html; do
            [ -e "$c" ] && printf '%s\n' "$c"
        done
    fi
    if webdetect_tomcat_present; then
        local home
        home="$(webdetect_tomcat_home 2>/dev/null)"
        if [ -n "$home" ]; then
            for c in docs examples manager host-manager; do
                [ -e "$home/webapps/$c" ] && printf '%s\n' "$home/webapps/$c"
            done
        fi
    fi
}

do_check() {
    if ! webdetect_any_httpd_present && ! webdetect_tomcat_present; then
        CHECK_DETAIL="Apache/Nginx/Tomcat 이 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    local found
    found="$(list_known_unnecessary_paths)"
    if [ -n "$found" ]; then
        CHECK_DETAIL="불필요 파일/디렉터리 존재: $(printf '%s' "$found" | tr '\n' ' ')"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="불필요 파일/디렉터리 없음."
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

    local removed="" p
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        if rm -rf -- "$p" 2>/dev/null; then
            removed="${removed}${p} "
        fi
    done < <(list_known_unnecessary_paths)

    if [ -z "$removed" ]; then
        FIX_DETAIL="삭제 대상 파일에 대한 쓰기 권한이 없어 조치를 수행하지 못함."
        return 2
    fi

    FIX_DETAIL="사전 정의된 불필요 파일/디렉터리를 제거함: ${removed% }"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-07 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
