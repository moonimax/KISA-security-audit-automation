#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/mysql_lib.sh"

readonly ITEM_CODE="D-08"
readonly ITEM_TITLE="안전한 암호화 알고리즘 사용"
readonly ACTION_TAG="승인요청"
readonly IMPACT="일반적인 경우 영향 없음"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    local rows
    rows="$(mysql_exec "SELECT CONCAT(user,'@',host,':',plugin) FROM mysql.user \
        WHERE plugin IN ('mysql_native_password','mysql_old_password');")"
    if [ $? -ne 0 ]; then
        CHECK_DETAIL="mysql 쿼리 실행 오류로 인증 플러그인 확인 실패"
        return "$KISA_EXIT_ERROR"
    fi
    if [ -z "$rows" ]; then
        CHECK_DETAIL="SHA-256 미만 알고리즘(mysql_native_password 등) 사용 계정 없음"
        return "$KISA_EXIT_GOOD"
    fi

    CHECK_DETAIL="취약 알고리즘 사용 계정: $(echo "$rows" | tr '\n' ' ')"
    return "$KISA_EXIT_VULN"
}

verify_and_get_status do_check

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
