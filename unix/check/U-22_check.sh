#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-22"
readonly ITEM_TITLE="/etc/services 파일 소유자 및 권한 설정"
readonly ACTION_TAG="자동조치"
readonly IMPACT="파일 소유자/권한만 변경되며 서비스 재시작이 불필요하고 포트-서비스명 조회 동작에는 영향이 없음"
readonly SEVERITY="하"
readonly TARGET_FILE="/etc/services"
readonly MAX_PERM=644

CHECK_DETAIL=""

do_check() {
    if [ ! -e "$TARGET_FILE" ]; then
        CHECK_DETAIL="${TARGET_FILE} 파일이 존재하지 않아 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    local owner perm reasons=()
    owner="$(stat -L -c '%U' "$TARGET_FILE" 2>/dev/null)"
    perm="$(stat -L -c '%a' "$TARGET_FILE" 2>/dev/null)"
    if [ -z "$owner" ] || [ -z "$perm" ]; then
        CHECK_DETAIL="${TARGET_FILE} 정보를 조회할 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    [ "$owner" != "root" ] && reasons+=("소유자가 root 가 아님(현재: ${owner})")
    [ "$perm" -gt "$MAX_PERM" ] && reasons+=("권한이 ${MAX_PERM} 을 초과함(현재: ${perm})")
    local other="${perm: -1}"
    [ $(( other & 2 )) -ne 0 ] && reasons+=("other 쓰기 권한이 부여됨(현재: ${perm})")

    if [ "${#reasons[@]}" -eq 0 ]; then
        CHECK_DETAIL="${TARGET_FILE} 소유자=${owner}, 권한=${perm} 로 기준을 충족함."
        return "$KISA_EXIT_GOOD"
    fi
    CHECK_DETAIL="$(IFS='; '; echo "${reasons[*]}")"
    return "$KISA_EXIT_VULN"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
