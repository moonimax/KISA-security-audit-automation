#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-20"
readonly ITEM_TITLE="SSL/TLS 활성화"
readonly ACTION_TAG="승인요청"
readonly IMPACT="유효한 인증서/개인키가 없으면 조치할 수 없으며, 잘못된 인증서 적용 시 접속 오류가 발생할 수 있음"
readonly SEVERITY="상"

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

do_check() {
    if ! webdetect_apache_present && ! webdetect_nginx_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    local vuln="false" detail=""

    if webdetect_apache_present; then
        if apache_ssl_enabled; then
            detail="${detail}Apache: SSL/TLS(443, SSLEngine on) 활성화됨. "
        else
            vuln="true"
            detail="${detail}Apache: 443 VirtualHost/SSLEngine on 설정을 찾지 못함. "
        fi
    fi

    if webdetect_nginx_present; then
        if nginx_ssl_enabled; then
            detail="${detail}Nginx: SSL/TLS(listen 443 ssl) 활성화됨. "
        else
            vuln="true"
            detail="${detail}Nginx: listen 443 ssl 설정을 찾지 못함. "
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
