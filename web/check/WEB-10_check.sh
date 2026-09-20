#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-10"
readonly ITEM_TITLE="불필요한 프록시 설정 제한"
readonly ACTION_TAG="승인요청"
readonly IMPACT="정방향 프록시 기능을 비활성화하며, 이를 실제로 사용 중인 경우가 아니라면 영향 없음"
readonly SEVERITY="상"

CHECK_DETAIL=""

apache_open_proxy_enabled() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*ProxyRequests[[:space:]]+On' "$f" 2>/dev/null && return 0
    done < <(webdetect_apache_active_confs)
    return 1
}

do_check() {
    if ! webdetect_apache_present && ! webdetect_nginx_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    if webdetect_apache_present && apache_open_proxy_enabled; then
        CHECK_DETAIL="Apache: 'ProxyRequests On' 설정으로 정방향(오픈) 프록시가 활성화되어 있음."
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="정방향(오픈) 프록시 설정('ProxyRequests On')이 발견되지 않음. 역방향 프록시(ProxyPass 등) 사용 여부는 이 항목의 취약 판정 대상이 아님."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
