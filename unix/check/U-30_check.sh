#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-30"
readonly ITEM_TITLE="UMASK 설정 관리"
readonly ACTION_TAG="자동조치"
readonly IMPACT="설정 파일 값만 변경되며 서비스 재시작이 불필요함. 이미 로그인된 세션의 UMASK 는 바뀌지 않고, 신규 세션/프로세스부터 적용됨"
readonly SEVERITY="중"

CHECK_DETAIL=""

_umask_is_secure() {
    local val="$1"
    local last2="${val: -2}"
    local group="${last2:0:1}" other="${last2:1:1}"
    [ $(( group & 2 )) -ne 0 ] && [ $(( other & 2 )) -ne 0 ]
}

do_check() {
    local candidates=(/etc/profile /etc/bashrc /etc/bash.bashrc /etc/login.defs /etc/csh.login)
    local found_any="false" offenders=()

    for f in "${candidates[@]}"; do
        [ -r "$f" ] || continue
        local val
        val="$(grep -E '^[[:space:]]*UMASK[[:space:]]' "$f" 2>/dev/null \
            | grep -v '^[[:space:]]*#' | tail -n1 | awk '{print $2}')"
        [[ "$val" =~ ^[0-7]{3,4}$ ]] || continue

        found_any="true"
        if ! _umask_is_secure "$val"; then
            offenders+=("${f}(UMASK=${val})")
        fi
    done

    if [ "$found_any" = "false" ]; then
        CHECK_DETAIL="UMASK 설정을 어느 후보 파일에서도 찾을 수 없음."
        return "$KISA_EXIT_VULN"
    fi

    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="group 또는 other 쓰기 권한을 차단하지 않는 UMASK 설정 발견: $(IFS='; '; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="확인된 모든 UMASK 설정이 group/other 쓰기 권한을 차단함(예: 022 이상)."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
