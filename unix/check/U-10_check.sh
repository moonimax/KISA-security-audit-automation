#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-10"
readonly ITEM_TITLE="동일한 UID 금지"
readonly ACTION_TAG="승인요청"
readonly IMPACT="usermod -u 로 UID를 변경하면 해당 UID로 소유된 기존 파일들의 소유권이 자동으로 갱신되지 않아 파일 소유권 불일치가 발생할 수 있음. 어떤 계정의 UID를 남기고 어떤 계정을 변경할지도 관리자 판단이 필요한 파괴적 변경임"
readonly SEVERITY="중"

CHECK_DETAIL=""

do_check() {
    if [ ! -r /etc/passwd ]; then
        CHECK_DETAIL="/etc/passwd 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    local dup_uids
    dup_uids="$(awk -F: '{print $3}' /etc/passwd | sort -n | uniq -d | tr '\n' ',' | sed 's/,$//')"

    if [ -n "$dup_uids" ]; then
        local dup_accounts
        dup_accounts="$(awk -F: -v duplist=",$dup_uids," 'index(duplist, ","$3",") {print $1"(uid="$3")"}' /etc/passwd | tr '\n' ',' | sed 's/,$//')"
        CHECK_DETAIL="중복된 UID 발견(${dup_uids}): ${dup_accounts}"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="모든 계정의 UID가 고유함(중복 없음)."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
