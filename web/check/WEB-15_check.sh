#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-15"
readonly ITEM_TITLE="웹 서비스의 불필요한 스크립트 매핑 제거"
readonly ACTION_TAG="승인요청"
readonly IMPACT="어떤 매핑이 실제로 사용되지 않는지는 애플리케이션 지식이 필요해 자동 판단이 불가능함"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    local web_xml
    if ! web_xml="$(webdetect_tomcat_web_xml 2>/dev/null)"; then
        CHECK_DETAIL="Tomcat web.xml 을 찾을 수 없어 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    if [ ! -r "$web_xml" ]; then
        CHECK_DETAIL="${web_xml} 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    local suspicious
    suspicious="$(grep -oE '<url-pattern>[^<]*</url-pattern>' "$web_xml" 2>/dev/null \
        | grep -iE '\.(bak|old|tmp|swp|orig)(</url-pattern>)?$|~</url-pattern>$' || true)"

    if [ -n "$suspicious" ]; then
        CHECK_DETAIL="${web_xml} 에 백업/구버전 흔적이 있는 url-pattern 이 존재함(참고용, 관리자 검토 필요): $(printf '%s' "$suspicious" | tr '\n' ' ')"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="${web_xml} 에서 백업/구버전 흔적이 있는 url-pattern 을 찾지 못함."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
