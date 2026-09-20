#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-05"
readonly ITEM_TITLE="root 이외의 UID가 '0' 금지"
readonly ACTION_TAG="승인요청"
readonly IMPACT="UID 0 계정을 삭제하거나 UID를 변경하는 작업이며, 해당 계정이 실제로 사용 중인 프로세스/파일 소유권과 얽혀 있을 경우 서비스 장애나 권한 문제를 유발할 수 있는 파괴적 변경임"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    if [ ! -r /etc/passwd ]; then
        CHECK_DETAIL="/etc/passwd 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    local extra_root_accounts
    extra_root_accounts="$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd | tr '\n' ',' | sed 's/,$//')"

    if [ -n "$extra_root_accounts" ]; then
        CHECK_DETAIL="root 외 UID 0 계정 발견: ${extra_root_accounts}"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="UID 0 을 가진 계정은 root 뿐이며, 다른 UID 0 계정이 존재하지 않음."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
