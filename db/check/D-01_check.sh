#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/mysql_lib.sh"

readonly ITEM_CODE="D-01"
readonly ITEM_TITLE="기본 계정의 비밀번호, 정책 등을 변경하여 사용"
readonly ACTION_TAG="자동조치"
readonly IMPACT="불필요한 기본 계정의 사용 제한"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    local rows
    rows="$(mysql_exec "SELECT CONCAT(user,'@',host) FROM mysql.user \
        WHERE (authentication_string='' OR authentication_string IS NULL) \
        AND plugin NOT IN ('auth_socket','unix_socket');")"
    if [ $? -ne 0 ]; then
        CHECK_DETAIL="mysql 쿼리 실행 오류로 기본 계정 비밀번호 확인 실패"
        return "$KISA_EXIT_ERROR"
    fi

    if [ -z "$rows" ]; then
        CHECK_DETAIL="공백 비밀번호 계정 없음"
        return "$KISA_EXIT_GOOD"
    fi

    CHECK_DETAIL="공백 비밀번호 계정 발견: $(echo "$rows" | tr '\n' ' ')"
    return "$KISA_EXIT_VULN"
}

verify_and_get_status do_check

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
