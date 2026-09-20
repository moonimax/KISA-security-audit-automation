#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/mysql_lib.sh"

readonly ITEM_CODE="D-06"
readonly ITEM_TITLE="DB 사용자 계정을 개별적으로 부여하여 사용 (자동판정 불가, 수동 검토 필요)"
readonly ACTION_TAG="승인요청"
readonly IMPACT="일반적인 경우 영향 없음"
readonly SEVERITY="중"

CHECK_DETAIL=""

do_check() {
    local rows
    rows="$(mysql_exec "SELECT CONCAT(user,'@',host) FROM mysql.user \
        WHERE user REGEXP '^(app|shared|common|service|admin|db|sys)[_0-9]*\$';")"
    CHECK_DETAIL="공용 계정으로 의심되는 이름: ${rows:-없음(단, 실제 공유 여부는 접속 로그/운영 정책 확인 필요)}"
    return "$KISA_EXIT_MANUAL"
}

verify_and_get_status do_check

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
