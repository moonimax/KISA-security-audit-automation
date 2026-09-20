#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-21"
readonly ITEM_TITLE="HTTP 리디렉션"
readonly ACTION_TAG="승인요청"
readonly IMPACT="HTTPS 로 강제 전환하므로 TLS 가 정상 동작하지 않는 상태에서 적용하면 서비스 접근이 막힐 수 있음"
readonly SEVERITY="중"

CHECK_DETAIL=""

apache_ssl_enabled() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '<VirtualHost[^>]*:443' "$f" 2>/dev/null && grep -qiE '^[[:space:]]*SSLEngine[[:space:]]+on' "$f" 2>/dev/null && return 0
    done < <(webdetect_apache_active_confs)
    return 1
}
nginx_ssl_enabled() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*listen[[:space:]]+.*443[[:space:]]+.*ssl' "$f" 2>/dev/null && return 0
    done < <(webdetect_nginx_active_confs)
    return 1
}
apache_http_redirect_present() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '<VirtualHost[^>]*:80' "$f" 2>/dev/null || continue
        grep -qiE 'Redirect|RewriteRule.*https://' "$f" 2>/dev/null && return 0
    done < <(webdetect_apache_active_confs)
    return 1
}
nginx_http_redirect_present() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*listen[[:space:]]+80' "$f" 2>/dev/null || continue
        grep -qiE 'return[[:space:]]+30[12][[:space:]]+https://' "$f" 2>/dev/null && return 0
    done < <(webdetect_nginx_active_confs)
    return 1
}

do_check() {
    if ! webdetect_apache_present && ! webdetect_nginx_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    local vuln="false" detail=""

    if webdetect_apache_present; then
        if ! apache_ssl_enabled; then
            vuln="true"
            detail="${detail}Apache: SSL/TLS(WEB-20)가 먼저 구성되어야 리디렉션을 적용할 수 있음. "
        elif apache_http_redirect_present; then
            detail="${detail}Apache: HTTP->HTTPS 리디렉션 확인됨. "
        else
            vuln="true"
            detail="${detail}Apache: 80 포트에서 HTTPS 리디렉션을 찾지 못함. "
        fi
    fi

    if webdetect_nginx_present; then
        if ! nginx_ssl_enabled; then
            vuln="true"
            detail="${detail}Nginx: SSL/TLS(WEB-20)가 먼저 구성되어야 리디렉션을 적용할 수 있음. "
        elif nginx_http_redirect_present; then
            detail="${detail}Nginx: HTTP->HTTPS 리디렉션 확인됨. "
        else
            vuln="true"
            detail="${detail}Nginx: 80 포트에서 HTTPS 리디렉션을 찾지 못함. "
        fi
    fi

    CHECK_DETAIL="${detail% }"
    [ "$vuln" = "true" ] && return "$KISA_EXIT_VULN"
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
