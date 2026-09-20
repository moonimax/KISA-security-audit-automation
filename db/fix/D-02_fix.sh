#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/mysql_lib.sh"

readonly ITEM_CODE="D-02"
readonly ITEM_TITLE="데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용"
readonly ACTION_TAG="자동조치"
readonly IMPACT="Demonstration 계정 / Object 사용 불가 / 삭제된 계정 사용 불가"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    local rows testdb
    rows="$(mysql_exec "SELECT CONCAT(user,'@',host) FROM mysql.user \
        WHERE user IN ('test','guest','demo','anonymous','') ;")"
    if [ $? -ne 0 ]; then
        CHECK_DETAIL="mysql 쿼리 실행 오류로 불필요 계정 확인 실패"
        return "$KISA_EXIT_ERROR"
    fi
    testdb="$(mysql_exec "SHOW DATABASES LIKE 'test';")"
    if [ $? -ne 0 ]; then
        CHECK_DETAIL="mysql 쿼리 실행 오류로 test DB 확인 실패"
        return "$KISA_EXIT_ERROR"
    fi

    if [ -z "$rows" ] && [ -z "$testdb" ]; then
        CHECK_DETAIL="불필요 계정/test DB 없음"
        return "$KISA_EXIT_GOOD"
    fi

    local detail=""
    [ -n "$rows" ] && detail+="불필요 계정: $(echo "$rows" | tr '\n' ' ') "
    [ -n "$testdb" ] && detail+="test 데이터베이스 존재"
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

    local rows testdb fail=0
    rows="$(mysql_exec "SELECT CONCAT(user,'@',host) FROM mysql.user \
        WHERE user IN ('test','guest','demo','anonymous','') ;")"
    while IFS= read -r acct; do
        [ -z "$acct" ] && continue
        local user host user_esc host_esc
        user="${acct%@*}"; host="${acct#*@}"
        user_esc="$(sql_escape "$user")"; host_esc="$(sql_escape "$host")"
        if mysql_exec "DROP USER '${user_esc}'@'${host_esc}';" >/dev/null; then
            log_info "D-02: 불필요 계정 삭제 - ${acct}"
        else
            log_error "D-02: ${acct} 삭제 실패"
            fail=1
        fi
    done <<< "$rows"

    testdb="$(mysql_exec "SHOW DATABASES LIKE 'test';")"
    if [ -n "$testdb" ]; then
        if mysql_exec "DROP DATABASE IF EXISTS test;" >/dev/null; then
            log_info "D-02: test 데이터베이스 삭제"
        else
            log_error "D-02: test 데이터베이스 삭제 실패"
            fail=1
        fi
    fi
    mysql_exec "FLUSH PRIVILEGES;" >/dev/null

    if [ "$fail" -eq 0 ]; then
        FIX_DETAIL="불필요 계정 및 test 데이터베이스 삭제 완료."
        return "$KISA_EXIT_GOOD"
    fi
    FIX_DETAIL="일부 계정/DB 삭제에 실패함."
    return "$KISA_EXIT_ERROR"
}

do_fix
KISA_FIX_RC=$?
log_info "D-02 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
