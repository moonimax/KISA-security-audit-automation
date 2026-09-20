#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-07"
readonly ITEM_TITLE="불필요한 계정 제거"
readonly ACTION_TAG="승인요청"
readonly IMPACT="userdel 은 계정 및 홈 디렉토리 데이터를 삭제하는 파괴적 작업이며, 어떤 계정이 실제로 불필요한지는 업무 맥락에 대한 관리자의 주관적 판단이 반드시 필요함"
readonly SEVERITY="하"

readonly SUSPECT_PATTERN="^(test[0-9]*|guest[0-9]*|temp|temporary|demo|backdoor)$"

CHECK_DETAIL=""

do_check() {
    if [ ! -r /etc/passwd ]; then
        CHECK_DETAIL="/etc/passwd 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    local suspects
    suspects="$(awk -F: -v pat="$SUSPECT_PATTERN" \
        'BEGIN{IGNORECASE=1} tolower($1) ~ pat && $7 !~ /(nologin|false)$/ {print $1}' \
        /etc/passwd | tr '\n' ',' | sed 's/,$//')"

    if [ -n "$suspects" ]; then
        CHECK_DETAIL="로그인 가능한 임시/테스트성 의심 계정 발견(1차 스크리닝, 최종 삭제 여부는 관리자 확인 필요): ${suspects}"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="테스트/임시 성격의 로그인 가능 계정이 발견되지 않음."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
