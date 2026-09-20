#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-15"
readonly ITEM_TITLE="파일 및 디렉터리 소유자 설정"
readonly ACTION_TAG="승인요청"
readonly IMPACT="탐지된 파일의 실제 용도와 소유권 재지정(또는 삭제) 필요 여부는 관리자의 확인이 필요함. 소유자가 없는 파일은 삭제된 계정의 잔존물일 수도, 침해사고의 흔적일 수도 있어 자동으로 판단할 수 없는 항목임"
readonly SEVERITY="중"
readonly SCAN_TIMEOUT="${KISA_U15_SCAN_TIMEOUT:-30}"

CHECK_DETAIL=""

do_check() {
    if ! command -v find >/dev/null 2>&1; then
        CHECK_DETAIL="find 명령을 찾을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    local runner=(find / -xdev \( -nouser -o -nogroup \) -print)
    local result rc

    if command -v timeout >/dev/null 2>&1; then
        result="$(timeout "$SCAN_TIMEOUT" "${runner[@]}" 2>/dev/null | head -n 20)"
        rc=$?
    else
        result="$("${runner[@]}" 2>/dev/null | head -n 20)"
        rc=0
    fi

    if [ "$rc" -eq 124 ]; then
        CHECK_DETAIL="파일시스템 전체 스캔이 ${SCAN_TIMEOUT}초 내에 끝나지 않아 판정을 완료하지 못함(대형 파일시스템). 점검 시간대를 조정하거나 대상 경로를 좁혀 재시도 필요."
        return "$KISA_EXIT_FAIL"
    fi

    if [ -n "$result" ]; then
        local count sample
        count="$(printf '%s\n' "$result" | grep -c .)"
        sample="$(printf '%s\n' "$result" | tr '\n' ',' | sed 's/,$//')"
        CHECK_DETAIL="소유자/그룹 정보가 유효하지 않은 파일 ${count}건(최대 20건 표시) 발견: ${sample}"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="루트 파일시스템 내에서 소유자/그룹이 존재하지 않는 파일을 발견하지 못함."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
