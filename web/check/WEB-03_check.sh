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

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
