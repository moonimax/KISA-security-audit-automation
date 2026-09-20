#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/mysql_lib.sh"

readonly ITEM_CODE="D-03"
readonly ITEM_TITLE="비밀번호의 사용기간 및 복잡도를 기관의 정책에 맞도록 설정"
readonly ACTION_TAG="자동조치"
readonly IMPACT="주기적인 비밀번호 변경 필요"
readonly SEVERITY="상"

CHECK_DETAIL=""
CHECK_EVIDENCE=""

do_check() {
    local policy lifetime
    policy="$(mysql_exec "SHOW VARIABLES LIKE 'validate_password%';")"
    if [ $? -ne 0 ]; then
        CHECK_DETAIL="mysql 쿼리 실행 오류로 비밀번호 정책 확인 실패"
        return "$KISA_EXIT_ERROR"
    fi
    lifetime="$(mysql_exec "SELECT @@default_password_lifetime;")"
    if [ $? -ne 0 ]; then
        CHECK_DETAIL="mysql 쿼리 실행 오류로 비밀번호 유효기간 확인 실패"
        return "$KISA_EXIT_ERROR"
    fi
    CHECK_EVIDENCE="$(evidence_json \
        "validate_password" "$([ -n "$policy" ] && printf '활성화' || printf '미설치')" \
        "비밀번호 최대 사용 기간" "${lifetime:-미설정}" \
        "판정 기준" "validate_password 활성화 및 사용 기간 1일 이상")"

    if [ -n "$policy" ] && [ "${lifetime:-0}" -gt 0 ] 2>/dev/null; then
        CHECK_DETAIL="validate_password 활성화, default_password_lifetime=${lifetime}"
        return "$KISA_EXIT_GOOD"
    fi

    local detail=""
    [ -z "$policy" ] && detail+="validate_password 컴포넌트/플러그인 미설치 "
    { [ -z "${lifetime:-}" ] || [ "${lifetime:-0}" -eq 0 ]; } 2>/dev/null && detail+="default_password_lifetime=0(무제한)"
    CHECK_DETAIL="$detail"
    return "$KISA_EXIT_VULN"
}

verify_and_get_status do_check

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY" "$CHECK_EVIDENCE"
