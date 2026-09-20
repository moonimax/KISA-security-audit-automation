#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-31"
readonly ITEM_TITLE="홈 디렉토리 소유자 및 권한 설정"
readonly ACTION_TAG="자동조치"
readonly IMPACT="홈 디렉토리 소유자/권한만 변경되며 서비스 재시작이 불필요함. 다음 로그인부터 반영되고 기존 세션에는 영향이 없음"
readonly SEVERITY="중"
readonly LOGIN_DEFS="/etc/login.defs"

CHECK_DETAIL=""

do_check() {
    if [ ! -r /etc/passwd ]; then
        CHECK_DETAIL="/etc/passwd 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    local uid_min
    uid_min="$(awk '/^[[:space:]]*UID_MIN[[:space:]]/{print $2; exit}' "$LOGIN_DEFS" 2>/dev/null)"
    uid_min="${uid_min:-1000}"

    local offenders=() count=0
    while IFS=: read -r uname _ uid _ _ home _; do
        [ -z "$home" ] && continue
        { [ "$uid" -ge "$uid_min" ] || [ "$uid" -eq 0 ]; } || continue
        [ -d "$home" ] || continue

        local owner perm
        owner="$(stat -L -c '%U' "$home" 2>/dev/null)"
        perm="$(stat -L -c '%a' "$home" 2>/dev/null)"
        [ -z "$owner" ] || [ -z "$perm" ] && continue
        local perm_last2="${perm: -2}"
        local group="${perm_last2:0:1}" other="${perm_last2:1:1}"
        if { [ "$owner" != "$uname" ] && [ "$owner" != "root" ]; } || [ $(( group & 2 )) -ne 0 ] || [ $(( other & 2 )) -ne 0 ]; then
            count=$((count + 1))
            [ "${#offenders[@]}" -lt 15 ] && offenders+=("${home}(owner=${owner},perm=${perm})")
        fi
    done < /etc/passwd

    if [ "$count" -gt 0 ]; then
        CHECK_DETAIL="소유자/권한이 기준을 벗어난 홈 디렉토리 ${count}건(최대 15건 표시) 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="점검된 실사용자 홈 디렉토리(UID>=${uid_min} 및 root) 모두 소유자 및 권한 기준을 충족함."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
