#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-26"
readonly ITEM_TITLE="/dev에 존재하지 않는 device 파일 점검"
readonly ACTION_TAG="승인요청"
readonly IMPACT="발견된 디바이스 파일이 정상 설치 과정의 잔재인지 은닉 채널인지 판단이 필요하며, 삭제(rm)는 되돌릴 수 없는 파괴적 변경이라 관리자 확인 없이 자동 실행하지 않음"
readonly SEVERITY="상"
readonly SCAN_TIMEOUT="${KISA_U26_SCAN_TIMEOUT:-30}"

CHECK_DETAIL=""

do_check() {
    command -v find >/dev/null 2>&1 || { CHECK_DETAIL="find 명령을 찾을 수 없어 판정이 불가능함."; return "$KISA_EXIT_FAIL"; }
    [ -d /dev ] || { CHECK_DETAIL="/dev 디렉토리가 없어 판정이 불가능함."; return "$KISA_EXIT_FAIL"; }
    local result rc
    if command -v timeout >/dev/null 2>&1; then
        result="$(timeout "$SCAN_TIMEOUT" find /dev -xdev -type f -print 2>/dev/null)"; rc=$?
    else
        result="$(find /dev -xdev -type f -print 2>/dev/null)"; rc=$?
    fi
    [ "$rc" -eq 124 ] && { CHECK_DETAIL="/dev 일반 파일 스캔이 ${SCAN_TIMEOUT}초 내에 끝나지 않음."; return "$KISA_EXIT_FAIL"; }
    [ "$rc" -eq 0 ] || { CHECK_DETAIL="/dev 일반 파일 스캔 명령이 실패함(rc=$rc)."; return "$KISA_EXIT_FAIL"; }
    if [ -n "$result" ]; then
        CHECK_DETAIL="/dev 내부 일반 파일 $(printf '%s\n' "$result" | grep -c .)건 발견: $(printf '%s\n' "$result" | tr '\n' ',' | sed 's/,$//')"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="/dev 내부에 일반 파일이 존재하지 않음."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
