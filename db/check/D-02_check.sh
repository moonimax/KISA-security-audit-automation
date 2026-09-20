#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/mysql_lib.sh"

readonly ITEM_CODE="D-02"
readonly ITEM_TITLE="데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용"
readonly ACTION_TAG="자동조치"
readonly IMPACT="Demonstration 계정 / Object 사용 불가 / 삭제된 계정 사용 불가"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    local rows testdb
    rows="$(mysql_exec "SELECT CONCAT(user,'@',host) FROM mysql.user \
        WHERE user IN ('test','guest','demo','anonymous','') ;")"
    if [ $? -ne 0 ]; then
        CHECK_DETAIL="mysql 쿼리 실행 오류로 불필요 계정 확인 실패"
        return "$KISA_EXIT_ERROR"
    fi
    testdb="$(mysql_exec "SHOW DATABASES LIKE 'test';")"
    if [ $? -ne 0 ]; then
        CHECK_DETAIL="mysql 쿼리 실행 오류로 test DB 확인 실패"
        return "$KISA_EXIT_ERROR"
    fi

    if [ -z "$rows" ] && [ -z "$testdb" ]; then
        CHECK_DETAIL="불필요 계정/test DB 없음"
        return "$KISA_EXIT_GOOD"
    fi

    local detail=""
    [ -n "$rows" ] && detail+="불필요 계정: $(echo "$rows" | tr '\n' ' ') "
    [ -n "$testdb" ] && detail+="test 데이터베이스 존재"
    CHECK_DETAIL="$detail"
    return "$KISA_EXIT_VULN"
}

verify_and_get_status do_check

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
