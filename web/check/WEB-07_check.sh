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
        CHECK_DETAIL="사전 정의된 불필요 파일/디렉터리가 존재함: $(printf '%s' "$found" | tr '\n' ' ')"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="사전 정의된 불필요 파일/디렉터리(매뉴얼/샘플/기본 앱)가 존재하지 않음."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
