#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-03"
readonly ITEM_TITLE="비밀번호 파일 권한 관리"
readonly ACTION_TAG="자동조치"
readonly IMPACT="파일 권한만 변경하며 서비스 재시작이 필요하지 않아 일반적인 경우 영향 없음"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    local users_xml
    if ! users_xml="$(webdetect_tomcat_users_xml 2>/dev/null)"; then
        CHECK_DETAIL="Tomcat tomcat-users.xml 을 찾을 수 없어 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    local perm
    perm="$(stat -c '%a' "$users_xml" 2>/dev/null)"
    if [ -z "$perm" ]; then
        CHECK_DETAIL="${users_xml} 의 권한을 조회할 수 없음."
        return "$KISA_EXIT_FAIL"
    fi
    if webdetect_perm_exceeds "$perm" 600; then
        CHECK_DETAIL="${users_xml} 권한이 ${perm} 로 600 을 초과함."
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="${users_xml} 권한이 ${perm} 로 600 이하임."
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

    local users_xml
    users_xml="$(webdetect_tomcat_users_xml 2>/dev/null)"
    if [ -z "$users_xml" ]; then
        FIX_DETAIL="조치 대상 파일을 다시 찾을 수 없어 조치를 수행하지 않음."
        return 2
    fi

    if chmod 600 "$users_xml" 2>/dev/null; then
        FIX_DETAIL="${users_xml} 권한을 600 으로 변경함."
        return 0
    fi
    FIX_DETAIL="${users_xml} 권한 변경(chmod)에 실패함."
    return 2
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-03 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
