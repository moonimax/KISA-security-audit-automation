#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-25"
readonly ITEM_TITLE="world writable 파일 점검"
readonly ACTION_TAG="승인요청"
readonly IMPACT="chmod 로 other 쓰기 권한만 제거하는 가역적 변경이지만, 메일 스풀·IPC 소켓·공유 로그 등 의도적으로 world-writable 로 구성된 파일이 존재할 수 있어 개별 파일에 대한 관리자 검토 없이 일괄 조치할 경우 정상 서비스가 깨질 위험이 있음"
readonly SEVERITY="상"
readonly SCAN_TIMEOUT="${KISA_U25_SCAN_TIMEOUT:-30}"

CHECK_DETAIL=""

do_check() {
    if ! command -v find >/dev/null 2>&1; then
        CHECK_DETAIL="find 명령을 찾을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    local result rc
    if command -v timeout >/dev/null 2>&1; then
        result="$(timeout "$SCAN_TIMEOUT" find / -xdev -type f -perm -0002 -print 2>/dev/null | head -n 30)"
        rc=$?
    else
        result="$(find / -xdev -type f -perm -0002 -print 2>/dev/null | head -n 30)"
        rc=0
    fi

    if [ "$rc" -eq 124 ]; then
        CHECK_DETAIL="world writable 파일 전체 스캔이 ${SCAN_TIMEOUT}초 내에 끝나지 않아 판정을 완료하지 못함."
        return "$KISA_EXIT_FAIL"
    fi

    if [ -n "$result" ]; then
        local count sample
        count="$(printf '%s\n' "$result" | grep -c .)"
        sample="$(printf '%s\n' "$result" | tr '\n' ',' | sed 's/,$//')"
        CHECK_DETAIL="world writable 일반 파일 ${count}건(최대 30건 표시) 발견: ${sample}"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="루트 파일시스템 내에서 world writable 파일을 발견하지 못함."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
