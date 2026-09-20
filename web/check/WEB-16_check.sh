#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-16"
readonly ITEM_TITLE="웹 서비스 헤더 정보 노출 제한"
readonly ACTION_TAG="자동조치"
readonly IMPACT="응답 헤더의 버전/서버 정보만 숨기며 일반적인 경우 서비스 영향 없음"
readonly SEVERITY="중"

CHECK_DETAIL=""
CHECK_EVIDENCE=""

apache_tokens_value() {
    local f last=""
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        local v
        v="$(grep -iE '^[[:space:]]*ServerTokens[[:space:]]' "$f" 2>/dev/null | tail -n1 | awk '{print $2}')"
        [ -n "$v" ] && last="$v"
    done < <(webdetect_apache_active_confs)
    printf '%s' "$last"
}

apache_signature_value() {
    local f last=""
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        local v
        v="$(grep -iE '^[[:space:]]*ServerSignature[[:space:]]' "$f" 2>/dev/null | tail -n1 | awk '{print $2}')"
        [ -n "$v" ] && last="$v"
    done < <(webdetect_apache_active_confs)
    printf '%s' "$last"
}

nginx_tokens_off() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*server_tokens[[:space:]]+off[[:space:]]*;' "$f" 2>/dev/null && return 0
    done < <(webdetect_nginx_active_confs)
    return 1
}

do_check() {
    if ! webdetect_apache_present && ! webdetect_nginx_present; then
        CHECK_EVIDENCE="$(evidence_json "웹 서버" "Apache/Nginx 미설치")"
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    local vuln="false" detail="" apache_tokens="해당 없음" apache_signature="해당 없음" nginx_tokens="해당 없음"

    if webdetect_apache_present; then
        local tok sig
        tok="$(apache_tokens_value)"
        sig="$(apache_signature_value)"
        apache_tokens="${tok:-미설정}"
        apache_signature="${sig:-미설정}"
        if [ "$tok" = "Prod" ] && [ "$sig" = "Off" ]; then
            detail="${detail}Apache: ServerTokens Prod / ServerSignature Off 확인됨. "
        else
            vuln="true"
            detail="${detail}Apache: ServerTokens='${tok:-미설정}', ServerSignature='${sig:-미설정}'(Prod/Off 필요). "
        fi
    fi

    if webdetect_nginx_present; then
        if nginx_tokens_off; then
            nginx_tokens="off"
            detail="${detail}Nginx: server_tokens off 확인됨. "
        else
            nginx_tokens="on 또는 미설정"
            vuln="true"
            detail="${detail}Nginx: server_tokens off 미설정(기본값 on). "
        fi
    fi

    CHECK_EVIDENCE="$(evidence_json "Apache ServerTokens" "$apache_tokens" "Apache ServerSignature" "$apache_signature" "Nginx server_tokens" "$nginx_tokens")"
    CHECK_DETAIL="${detail% }"
    [ "$vuln" = "true" ] && return "$KISA_EXIT_VULN"
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY" "$CHECK_EVIDENCE"
