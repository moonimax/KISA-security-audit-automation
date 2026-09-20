#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/mysql_lib.sh"

readonly ITEM_CODE="D-07"
readonly ITEM_TITLE="root 권한으로 서비스 구동 제한"
readonly ACTION_TAG="자동조치"
readonly IMPACT="일반적인 경우 영향 없음"
readonly SEVERITY="중"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    local proc_user cnf_user
    proc_user="$(ps -eo user,comm 2>/dev/null | awk '$2=="mysqld"{print $1; exit}')"
    cnf_user="$(grep -E '^\s*user\s*=' "$MY_CNF_PATH" 2>/dev/null | tail -1 | awk -F= '{gsub(/ /,"",$2); print $2}')"

    if [ -z "$proc_user" ]; then
        CHECK_DETAIL="로컬에서 mysqld 프로세스를 찾지 못함(원격/컨테이너 환경 여부 확인 필요)"
        return "$KISA_EXIT_MANUAL"
    elif [ "$proc_user" = "root" ]; then
        CHECK_DETAIL="mysqld 가 root 계정으로 구동 중"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="mysqld 구동 계정: $proc_user, my.cnf user=${cnf_user:-미설정}"
    return "$KISA_EXIT_GOOD"
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
    if [ "$current" -eq "$KISA_EXIT_MANUAL" ]; then
        FIX_DETAIL="로컬에서 mysqld 프로세스를 찾지 못해 자동 조치를 건너뜀(원격/컨테이너 환경 여부 확인 필요)."
        return "$KISA_EXIT_MANUAL"
    fi

    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 my.cnf 조치를 수행할 수 없음."
        return "$KISA_EXIT_ERROR"
    fi

    ensure_mysqld_block "D07-SERVICE-USER" "user=${MYSQLD_EXPECTED_USER}"
    FIX_DETAIL="my.cnf 의 user=${MYSQLD_EXPECTED_USER} 로 반영 완료. mysqld 데몬 재시작이 필요합니다(예: systemctl restart mysqld). 서비스 중단을 유발할 수 있는 재시작은 자동으로 수행하지 않았습니다."
    return "$KISA_EXIT_MANUAL"
}

do_fix
KISA_FIX_RC=$?
log_info "D-07 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
