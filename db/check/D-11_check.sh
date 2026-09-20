#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/mysql_lib.sh"

readonly ITEM_CODE="D-11"
readonly ITEM_TITLE="DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"
readonly ACTION_TAG="자동조치"
readonly IMPACT="일반 계정으로 시스템 테이블 접근 불가"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    local rows offenders=""
    rows="$(mysql_exec "SELECT DISTINCT grantee FROM information_schema.schema_privileges WHERE table_schema='mysql';")"
    if [ $? -ne 0 ]; then
        CHECK_DETAIL="mysql 쿼리 실행 오류로 mysql 스키마 접근 계정 확인 실패"
        return "$KISA_EXIT_ERROR"
    fi
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local acct
        acct="$(normalize_account "$line")"
        if ! list_contains "$acct" "$ALLOWED_ADMIN_ACCOUNTS"; then
            offenders+="$acct "
        fi
    done <<< "$rows"

    if [ -z "$offenders" ]; then
        CHECK_DETAIL="허용 목록 외 mysql 스키마 접근 계정 없음"
        return "$KISA_EXIT_GOOD"
    fi

    CHECK_DETAIL="mysql 스키마 접근 권한 보유(허용 목록 외): $offenders"
    return "$KISA_EXIT_VULN"
}

verify_and_get_status do_check

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
