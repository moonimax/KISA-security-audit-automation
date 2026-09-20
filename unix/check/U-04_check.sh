#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-04"
readonly ITEM_TITLE="비밀번호 파일 보호"
readonly ACTION_TAG="승인요청"
readonly IMPACT="pwconv 실행은 시스템 전체 계정의 인증 정보를 passwd -> shadow 체계로 변환하는 작업으로, 변환 중 오류 발생 시 전 계정 로그인 장애로 이어질 수 있는 고위험 작업임"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    if [ ! -r /etc/passwd ]; then
        CHECK_DETAIL="/etc/passwd 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    if [ ! -e /etc/shadow ]; then
        CHECK_DETAIL="/etc/shadow 파일이 존재하지 않아 shadow 패스워드 체계가 사용되고 있지 않음."
        return "$KISA_EXIT_VULN"
    fi

    local bad_count
    bad_count="$(awk -F: '$2!="x" && $2!="*" {c++} END{print c+0}' /etc/passwd)"

    if [ "$bad_count" -gt 0 ]; then
        CHECK_DETAIL="/etc/passwd 에 shadow('x') 를 사용하지 않는 계정이 ${bad_count}건 존재함(암호 필드가 직접 노출되어 있을 가능성)."
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="/etc/shadow 가 존재하고 /etc/passwd 의 모든 계정이 shadow 패스워드 체계('x')를 사용 중임."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
