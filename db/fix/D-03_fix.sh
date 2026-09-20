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
FIX_DETAIL=""

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

do_fix() {
    do_check
    local current=$?

    if [ "$current" -eq "$KISA_EXIT_GOOD" ]; then
        FIX_DETAIL="이미 양호 상태로 조치가 필요하지 않음."
        return "$KISA_EXIT_GOOD"
    fi
    if [ "$current" -eq "$KISA_EXIT_ERROR" ]; then
        FIX_DETAIL="조치 대상 상태를 확인할 수 없어 조치를 수행하지 않음."
        return "$KISA_EXIT_ERROR"
    fi

    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 my.cnf 조치를 수행할 수 없음."
        return "$KISA_EXIT_ERROR"
    fi

    local policy fail=0
    policy="$(mysql_exec "SHOW VARIABLES LIKE 'validate_password%';")"
    if [ -z "$policy" ]; then
        mysql_exec "INSTALL COMPONENT 'file://component_validate_password';" >/dev/null \
            || log_warn "D-03: validate_password 컴포넌트 설치 실패(이미 플러그인 형태로 설치되어 있을 수 있음)"
    fi
    mysql_exec "SET PERSIST validate_password.policy='${PASSWORD_POLICY}';" >/dev/null || fail=1
    mysql_exec "SET PERSIST validate_password.length=${PASSWORD_MIN_LENGTH};" >/dev/null || fail=1
    mysql_exec "SET PERSIST validate_password.mixed_case_count=${PASSWORD_MIXED_CASE_COUNT};" >/dev/null || fail=1
    mysql_exec "SET PERSIST validate_password.number_count=${PASSWORD_NUMBER_COUNT};" >/dev/null || fail=1
    mysql_exec "SET PERSIST validate_password.special_char_count=${PASSWORD_SPECIAL_CHAR_COUNT};" >/dev/null || fail=1
    mysql_exec "SET PERSIST default_password_lifetime=${PASSWORD_LIFETIME_DAYS};" >/dev/null || fail=1

    ensure_mysqld_block "D03-PASSWORD-POLICY" "validate_password.policy=${PASSWORD_POLICY}
validate_password.length=${PASSWORD_MIN_LENGTH}
validate_password.mixed_case_count=${PASSWORD_MIXED_CASE_COUNT}
validate_password.number_count=${PASSWORD_NUMBER_COUNT}
validate_password.special_char_count=${PASSWORD_SPECIAL_CHAR_COUNT}
default_password_lifetime=${PASSWORD_LIFETIME_DAYS}"

    if [ "$fail" -eq 0 ]; then
        FIX_DETAIL="비밀번호 정책(정책=${PASSWORD_POLICY}, 최소길이=${PASSWORD_MIN_LENGTH}, 유효기간=${PASSWORD_LIFETIME_DAYS}일) 적용 완료(SET PERSIST + my.cnf 반영)."
        return "$KISA_EXIT_GOOD"
    fi
    FIX_DETAIL="일부 비밀번호 정책 설정 적용에 실패함."
    return "$KISA_EXIT_ERROR"
}

do_fix
KISA_FIX_RC=$?
log_info "D-03 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
