#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-13"
readonly ITEM_TITLE="웹 서비스 설정 파일 노출 제한"
readonly ACTION_TAG="자동조치"
readonly IMPACT="파일 권한만 변경하며 서비스 재시작이 필요하지 않아 일반적인 경우 영향 없음"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    local server_xml
    if ! server_xml="$(webdetect_tomcat_server_xml 2>/dev/null)"; then
        CHECK_DETAIL="Tomcat server.xml 을 찾을 수 없어 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    if [ ! -r "$server_xml" ]; then
        CHECK_DETAIL="${server_xml} 를 읽을 수 없음."
        return "$KISA_EXIT_FAIL"
    fi
    if ! grep -qi 'javax.sql.DataSource' "$server_xml" 2>/dev/null; then
        CHECK_DETAIL="DB 연결 리소스 없음(해당 없음)."
        return "$KISA_EXIT_GOOD"
    fi
    local perm
    perm="$(stat -c '%a' "$server_xml" 2>/dev/null)"
    [ -z "$perm" ] && { CHECK_DETAIL="권한 조회 불가."; return "$KISA_EXIT_FAIL"; }
    if webdetect_perm_exceeds "$perm" 600; then
        CHECK_DETAIL="${server_xml} 권한 ${perm} 초과."
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="${server_xml} 권한 ${perm} 양호."
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

    local server_xml
    server_xml="$(webdetect_tomcat_server_xml 2>/dev/null)"
    if [ -z "$server_xml" ]; then
        FIX_DETAIL="조치 대상 파일을 다시 찾을 수 없음."
        return 2
    fi
    if chmod 600 "$server_xml" 2>/dev/null; then
        FIX_DETAIL="${server_xml} 권한을 600 으로 변경함."
        return 0
    fi
    FIX_DETAIL="${server_xml} 권한 변경(chmod)에 실패함."
    return 2
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-13 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
