#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/mysql_lib.sh"

readonly ITEM_CODE="D-10"
readonly ITEM_TITLE="원격에서 DB 서버로의 접속 제한"
readonly ACTION_TAG="승인요청"
readonly IMPACT="허용되지 않은 IP에서 접속 제한"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    local rows
    rows="$(mysql_exec "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE host='%';")"
    if [ $? -ne 0 ]; then
        CHECK_DETAIL="mysql 쿼리 실행 오류로 원격 접속 계정 확인 실패"
        return "$KISA_EXIT_ERROR"
    fi
    if [ -z "$rows" ]; then
        CHECK_DETAIL="host='%' 계정 없음"
        return "$KISA_EXIT_GOOD"
    fi

    CHECK_DETAIL="모든 호스트 접속 허용 계정(host='%'): $(echo "$rows" | tr '\n' ' ')"
    return "$KISA_EXIT_VULN"
}

verify_and_get_status do_check

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
