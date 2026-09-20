#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/mysql_lib.sh"

readonly ITEM_CODE="D-04"
readonly ITEM_TITLE="데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용"
readonly ACTION_TAG="자동조치"
readonly IMPACT="일반적인 경우 영향 없음"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    local rows offenders=""
    rows="$(mysql_exec "SELECT DISTINCT grantee FROM information_schema.user_privileges WHERE privilege_type='SUPER';")"
    if [ $? -ne 0 ]; then
        CHECK_DETAIL="mysql 쿼리 실행 오류로 SUPER 권한 계정 확인 실패"
        return "$KISA_EXIT_ERROR"
    fi
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local acct
        acct="$(normalize_account "$line")"
        if ! list_contains "$acct" "$ALLOWED_ADMIN_ACCOUNTS"; then
            offenders+="$acct "
        fi
    done <<< "$rows"

    if [ -z "$offenders" ]; then
        CHECK_DETAIL="허용 목록 외 SUPER 권한 계정 없음"
        return "$KISA_EXIT_GOOD"
    fi

    CHECK_DETAIL="허용 목록 외 SUPER 권한 보유 계정: $offenders"
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

    local rows fail=0 revoked=""
    rows="$(mysql_exec "SELECT DISTINCT grantee FROM information_schema.user_privileges WHERE privilege_type='SUPER';")"
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local acct
        acct="$(normalize_account "$line")"
        list_contains "$acct" "$ALLOWED_ADMIN_ACCOUNTS" && continue
        local user host user_esc host_esc
        user="${acct%@*}"; host="${acct#*@}"
        user_esc="$(sql_escape "$user")"; host_esc="$(sql_escape "$host")"
        if mysql_exec "REVOKE SUPER ON *.* FROM '${user_esc}'@'${host_esc}';" >/dev/null; then
            revoked+="$acct "
        else
            log_error "D-04: ${acct} SUPER 권한 회수 실패"
            fail=1
        fi
    done <<< "$rows"
    mysql_exec "FLUSH PRIVILEGES;" >/dev/null

    if [ "$fail" -eq 0 ]; then
        FIX_DETAIL="허용 목록 외 계정의 SUPER 권한 회수 완료: ${revoked:-없음}"
        return "$KISA_EXIT_GOOD"
    fi
    FIX_DETAIL="일부 계정의 SUPER 권한 회수 실패."
    return "$KISA_EXIT_ERROR"
}

do_fix
KISA_FIX_RC=$?
log_info "D-04 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
