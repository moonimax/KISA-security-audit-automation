#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/mysql_lib.sh"

readonly ITEM_CODE="D-10"
readonly ITEM_TITLE="원격에서 DB 서버로의 접속 제한"
readonly ACTION_TAG="승인요청"
readonly IMPACT="허용되지 않은 IP에서 접속 제한"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    local rows
    rows="$(mysql_exec "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE host='%';")"
    if [ $? -ne 0 ]; then
        CHECK_DETAIL="mysql 쿼리 실행 오류로 원격 접속 계정 확인 실패"
        return "$KISA_EXIT_ERROR"
    fi
    if [ -z "$rows" ]; then
        CHECK_DETAIL="host='%' 계정 없음"
        return "$KISA_EXIT_GOOD"
    fi

    CHECK_DETAIL="모든 호스트 접속 허용 계정(host='%'): $(echo "$rows" | tr '\n' ' ')"
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): host='%' 계정을 제한된 호스트로 전환하면 애플리케이션 접속이 단절될 위험이 있습니다. 승인 후 KISA_APPROVAL=true 로 재실행하세요."
        return "$KISA_EXIT_VULN"
    fi

    if [ -z "${ALLOWED_REMOTE_HOSTS// /}" ]; then
        FIX_DETAIL="ALLOWED_REMOTE_HOSTS 가 비어있어 자동 조치를 건너뜀. 허용할 IP를 설정 파일에 지정하세요."
        return "$KISA_EXIT_MANUAL"
    fi

    local rows fail=0
    rows="$(mysql_exec "SELECT user FROM mysql.user WHERE host='%';")"
    while IFS= read -r user; do
        [ -z "$user" ] && continue
        local plugin authstr grants user_esc authstr_esc
        plugin="$(mysql_exec "SELECT plugin FROM mysql.user WHERE user='${user}' AND host='%';")"
        authstr="$(mysql_exec "SELECT authentication_string FROM mysql.user WHERE user='${user}' AND host='%';")"
        grants="$(mysql_exec "SHOW GRANTS FOR '${user}'@'%';")"

        user_esc="$(sql_escape "$user")"; authstr_esc="$(sql_escape "$authstr")"
        for newhost in $ALLOWED_REMOTE_HOSTS; do
            local newhost_esc; newhost_esc="$(sql_escape "$newhost")"
            mysql_exec "CREATE USER IF NOT EXISTS '${user_esc}'@'${newhost_esc}' IDENTIFIED WITH ${plugin} AS '${authstr_esc}';" >/dev/null \
                || { log_error "D-10: '${user}'@'${newhost}' 계정 생성 실패"; fail=1; }
            while IFS= read -r grant_line; do
                [ -z "$grant_line" ] && continue
                local new_grant
                new_grant="$(echo "$grant_line" | sed "s/@'%'/@'${newhost}'/g; s/\$/;/")"
                mysql_exec "$new_grant" >/dev/null || { log_error "D-10: '${user}'@'${newhost}' 권한 복제 실패"; fail=1; }
            done <<< "$grants"
        done
        mysql_exec "DROP USER '${user}'@'%';" >/dev/null || { log_error "D-10: 원본 '${user}'@'%' 계정 삭제 실패"; fail=1; }
    done <<< "$rows"
    mysql_exec "FLUSH PRIVILEGES;" >/dev/null

    if [ "$fail" -eq 0 ]; then
        FIX_DETAIL="host='%' 계정을 허용 호스트(${ALLOWED_REMOTE_HOSTS})로 전환 완료."
        return "$KISA_EXIT_GOOD"
    fi
    FIX_DETAIL="일부 계정 전환에 실패함."
    return "$KISA_EXIT_ERROR"
}

do_fix
KISA_FIX_RC=$?
log_info "D-10 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
