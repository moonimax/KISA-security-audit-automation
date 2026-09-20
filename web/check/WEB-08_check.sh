#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-08"
readonly ITEM_TITLE="웹 서비스 파일 업로드 및 다운로드 용량 제한"
readonly ACTION_TAG="자동조치"
readonly IMPACT="업로드/다운로드 최대 용량을 10MB로 제한하며, 이보다 큰 파일을 다루는 서비스가 없다면 영향 없음"
readonly SEVERITY="하"

CHECK_DETAIL=""

apache_has_limit() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*LimitRequestBody[[:space:]]+[1-9]' "$f" 2>/dev/null && return 0
    done < <(webdetect_apache_active_confs)
    return 1
}

nginx_has_limit() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*client_max_body_size[[:space:]]' "$f" 2>/dev/null && return 0
    done < <(webdetect_nginx_active_confs)
    return 1
}

do_check() {
    if ! webdetect_any_httpd_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    local vuln="false" detail=""

    if webdetect_apache_present; then
        if apache_has_limit; then
            detail="${detail}Apache: LimitRequestBody 설정됨. "
        else
            vuln="true"
            detail="${detail}Apache: LimitRequestBody 설정 없음(기본값 무제한). "
        fi
    fi

    if webdetect_nginx_present; then
        if nginx_has_limit; then
            detail="${detail}Nginx: client_max_body_size 설정됨. "
        else
            vuln="true"
            detail="${detail}Nginx: client_max_body_size 설정 없음(기본값 1m이나 명시 설정 권고). "
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
