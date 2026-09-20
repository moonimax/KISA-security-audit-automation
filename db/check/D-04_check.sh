#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/mysql_lib.sh"

readonly ITEM_CODE="D-04"
readonly ITEM_TITLE="데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용"
readonly ACTION_TAG="자동조치"
readonly IMPACT="일반적인 경우 영향 없음"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    local rows offenders=""
    rows="$(mysql_exec "SELECT DISTINCT grantee FROM information_schema.user_privileges WHERE privilege_type='SUPER';")"
    if [ $? -ne 0 ]; then
        CHECK_DETAIL="mysql 쿼리 실행 오류로 SUPER 권한 계정 확인 실패"
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
        CHECK_DETAIL="허용 목록 외 SUPER 권한 계정 없음"
        return "$KISA_EXIT_GOOD"
    fi

    CHECK_DETAIL="허용 목록 외 SUPER 권한 보유 계정: $offenders"
    return "$KISA_EXIT_VULN"
}

verify_and_get_status do_check

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
