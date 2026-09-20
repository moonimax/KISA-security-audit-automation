#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-08"
readonly ITEM_TITLE="관리자 그룹에 최소한의 계정 포함"
readonly ACTION_TAG="승인요청"
readonly IMPACT="root 권한 그룹(gid 0)에서 계정을 제외하는 작업으로, 어떤 계정을 남겨야 하는지는 운영 정책에 대한 관리자의 판단이 필요함. 잘못 제외 시 정상 운영자의 관리자 권한이 상실될 수 있음"
readonly SEVERITY="중"

CHECK_DETAIL=""

do_check() {
    if [ ! -r /etc/group ]; then
        CHECK_DETAIL="/etc/group 을 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    local root_group_line members
    root_group_line="$(awk -F: '$3==0 {print; exit}' /etc/group)"

    if [ -z "$root_group_line" ]; then
        CHECK_DETAIL="/etc/group 에서 GID 0 그룹을 찾을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    members="$(printf '%s' "$root_group_line" | awk -F: '{print $4}')"

    if [ -n "$members" ]; then
        CHECK_DETAIL="GID 0(관리자) 그룹에 root 외 부가 계정이 포함되어 있음: ${members}"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="GID 0(관리자) 그룹의 부가 멤버 목록이 비어 있어 최소 권한 원칙을 충족함."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
