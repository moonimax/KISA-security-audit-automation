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
FIX_DETAIL=""

do_check() {
    local web_xml
    if ! web_xml="$(webdetect_tomcat_web_xml 2>/dev/null)"; then
        CHECK_DETAIL="Tomcat web.xml 을 찾을 수 없어 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    if [ ! -r "$web_xml" ]; then
        CHECK_DETAIL="${web_xml} 를 읽을 수 없음."
        return "$KISA_EXIT_FAIL"
    fi
    local suspicious
    suspicious="$(grep -oE '<url-pattern>[^<]*</url-pattern>' "$web_xml" 2>/dev/null \
        | grep -iE '\.(bak|old|tmp|swp|orig)(</url-pattern>)?$|~</url-pattern>$' || true)"
    if [ -n "$suspicious" ]; then
        CHECK_DETAIL="의심스러운 url-pattern: $(printf '%s' "$suspicious" | tr '\n' ' ')"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="의심스러운 url-pattern 없음."
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

    if ! is_approved; then
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 실제 사용 여부는 애플리케이션 지식이 필요함. 승인 후 KISA_APPROVAL=true 로 재실행해도 자동 변경은 수행되지 않으며 후보 목록만 재확인됨."
        return 1
    fi

    local web_xml
    web_xml="$(webdetect_tomcat_web_xml 2>/dev/null)"
    FIX_DETAIL="자동 삭제는 애플리케이션 오동작 위험이 있어 수행하지 않음. ${web_xml:-web.xml} 에서 위 CHECK_DETAIL 에 나열된 <servlet-mapping> 항목의 실제 사용 여부를 관리자가 직접 확인 후 불필요한 항목만 수동으로 제거해야 함. 시스템 변경 없이 안내만 반환함."
    return 1
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-15 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
