#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-09"
readonly ITEM_TITLE="불필요하거나 계정과 연결되지 않은 그룹 제거"
readonly ACTION_TAG="승인요청"
readonly IMPACT="계정과 연결되지 않은 그룹도 서비스 예약 그룹일 수 있어 관리자 검토가 필요함"
readonly SEVERITY="하"

CHECK_DETAIL=""

_find_unlinked_groups() {
    awk -F: '
        NR==FNR { primary[$4]=1; next }
        !($3 in primary) && $4=="" { print $1 "(gid=" $3 ")" }
    ' /etc/passwd /etc/group
}

do_check() {
    if [ ! -r /etc/passwd ] || [ ! -r /etc/group ]; then
        CHECK_DETAIL="/etc/passwd 또는 /etc/group 을 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    local orphans
    orphans="$(_find_unlinked_groups | tr '\n' ',' | sed 's/,$//')"
    if [ -n "$orphans" ]; then
        CHECK_DETAIL="기본 GID나 보조 구성원으로 어떤 계정과도 연결되지 않은 그룹 발견(업무상 필요 여부 확인 필요): $orphans"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="/etc/group에서 계정과 연결되지 않은 그룹이 발견되지 않음."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
