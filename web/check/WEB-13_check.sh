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

do_check() {
    local server_xml
    if ! server_xml="$(webdetect_tomcat_server_xml 2>/dev/null)"; then
        CHECK_DETAIL="Tomcat server.xml 을 찾을 수 없어 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    if [ ! -r "$server_xml" ]; then
        CHECK_DETAIL="${server_xml} 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    if ! grep -qi 'javax.sql.DataSource' "$server_xml" 2>/dev/null; then
        CHECK_DETAIL="${server_xml} 에 DB 연결 리소스(javax.sql.DataSource)가 설정되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    local perm
    perm="$(stat -c '%a' "$server_xml" 2>/dev/null)"
    if [ -z "$perm" ]; then
        CHECK_DETAIL="${server_xml} 권한을 조회할 수 없음."
        return "$KISA_EXIT_FAIL"
    fi
    if webdetect_perm_exceeds "$perm" 600; then
        CHECK_DETAIL="${server_xml} 에 DB 연결 리소스가 있고 권한이 ${perm} 로 600 을 초과함."
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="${server_xml} 에 DB 연결 리소스가 있으나 권한이 ${perm} 로 600 이하임."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
