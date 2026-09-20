#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/mysql_lib.sh"

readonly ITEM_CODE="D-08"
readonly ITEM_TITLE="안전한 암호화 알고리즘 사용"
readonly ACTION_TAG="승인요청"
readonly IMPACT="일반적인 경우 영향 없음"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    local rows
    rows="$(mysql_exec "SELECT CONCAT(user,'@',host,':',plugin) FROM mysql.user \
        WHERE plugin IN ('mysql_native_password','mysql_old_password');")"
    if [ $? -ne 0 ]; then
        CHECK_DETAIL="mysql 쿼리 실행 오류로 인증 플러그인 확인 실패"
        return "$KISA_EXIT_ERROR"
    fi
    if [ -z "$rows" ]; then
        CHECK_DETAIL="SHA-256 미만 알고리즘(mysql_native_password 등) 사용 계정 없음"
        return "$KISA_EXIT_GOOD"
    fi

    CHECK_DETAIL="취약 알고리즘 사용 계정: $(echo "$rows" | tr '\n' ' ')"
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

    if [ "$ACTION_TAG" = "승인요청" ] && ! is_approved; then
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 인증 플러그인 전환 시 비밀번호가 재발급되어 애플리케이션 접속 정보 갱신이 필요합니다. 승인 후 KISA_APPROVAL=true 로 재실행하세요."
        return "$KISA_EXIT_VULN"
    fi

    local rows fail=0
    local pwfile="/root/mysql_security_d08_new_passwords_$(date '+%Y%m%d_%H%M%S').txt"
    rows="$(mysql_exec "SELECT CONCAT(user,'@',host) FROM mysql.user \
        WHERE plugin IN ('mysql_native_password','mysql_old_password');")"
    while IFS= read -r acct; do
        [ -z "$acct" ] && continue
        local user host newpw user_esc host_esc
        user="${acct%@*}"; host="${acct#*@}"
        user_esc="$(sql_escape "$user")"; host_esc="$(sql_escape "$host")"
        newpw="$(random_password)"
        if mysql_exec "ALTER USER '${user_esc}'@'${host_esc}' IDENTIFIED WITH caching_sha2_password BY '${newpw}';" >/dev/null; then
            echo "${user}@${host} : ${newpw}" >> "$pwfile"
            log_info "D-08: ${acct} 인증 플러그인을 caching_sha2_password 로 전환(비밀번호 재발급)"
        else
            log_error "D-08: ${acct} 인증 플러그인 전환 실패"
            fail=1
        fi
    done <<< "$rows"

    if [ -f "$pwfile" ]; then
        chmod 600 "$pwfile"
        FIX_DETAIL="인증 플러그인을 caching_sha2_password 로 전환 완료(비밀번호 재발급). 신규 비밀번호 파일: ${pwfile} (반드시 안전하게 보관 후 삭제할 것)"
    else
        FIX_DETAIL="조치 대상 계정 처리에 실패함."
        fail=1
    fi

    [ "$fail" -eq 0 ] && return "$KISA_EXIT_GOOD" || return "$KISA_EXIT_ERROR"
}

do_fix
KISA_FIX_RC=$?
log_info "D-08 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
