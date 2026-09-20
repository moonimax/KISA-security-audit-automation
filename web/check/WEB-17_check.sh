#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-17"
readonly ITEM_TITLE="웹 서비스 가상 디렉토리 삭제"
readonly ACTION_TAG="승인요청"
readonly IMPACT="어떤 가상 디렉터리가 실제 사용 중인지는 애플리케이션 지식이 필요해 자동 판단이 불가능함"
readonly SEVERITY="중"

CHECK_DETAIL=""

list_apache_aliases() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -iE '^[[:space:]]*(Alias|ScriptAlias)[[:space:]]' "$f" 2>/dev/null | grep -viE '^[[:space:]]*(Alias|ScriptAlias)[[:space:]]+/((icons|cgi-bin)/?)([[:space:]]|$)'
    done < <(webdetect_apache_active_confs)
}

list_nginx_aliases() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -iE '^[[:space:]]*alias[[:space:]]' "$f" 2>/dev/null
    done < <(webdetect_nginx_active_confs)
}

do_check() {
    if ! webdetect_apache_present && ! webdetect_nginx_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    local apache_aliases="" nginx_aliases=""
    webdetect_apache_present && apache_aliases="$(list_apache_aliases)"
    webdetect_nginx_present && nginx_aliases="$(list_nginx_aliases)"

    if [ -n "$apache_aliases" ] || [ -n "$nginx_aliases" ]; then
        local a_count=0 n_count=0
        [ -n "$apache_aliases" ] && a_count="$(printf '%s\n' "$apache_aliases" | grep -c .)"
        [ -n "$nginx_aliases" ] && n_count="$(printf '%s\n' "$nginx_aliases" | grep -c .)"
        local count=$(( a_count + n_count ))
        CHECK_DETAIL="[관리자 수동 조치 필요] Alias/ScriptAlias(가상 디렉터리) 지시자 ${count}건 발견 - 실제 사용 여부는 관리자 검토 필요, 자동/승인조치로 처리되지 않는 항목(참고용 판정)."
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="Alias/ScriptAlias(가상 디렉터리) 지시자를 찾지 못함."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
