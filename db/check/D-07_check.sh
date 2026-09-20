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
CHECK_EVIDENCE=""

do_check() {
    local proc_user cnf_user
    proc_user="$(ps -eo user,comm 2>/dev/null | awk '$2=="mysqld"{print $1; exit}')"
    cnf_user="$(grep -E '^\s*user\s*=' "$MY_CNF_PATH" 2>/dev/null | tail -1 | awk -F= '{gsub(/ /,"",$2); print $2}')"
    CHECK_EVIDENCE="$(evidence_json "mysqld 실행 계정" "${proc_user:-확인 불가}" "my.cnf user" "${cnf_user:-미설정}")"

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

verify_and_get_status do_check

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY" "$CHECK_EVIDENCE"
