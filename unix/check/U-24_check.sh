#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-24"
readonly ITEM_TITLE="사용자, 시스템 환경변수 파일 소유자 및 권한 설정"
readonly ACTION_TAG="자동조치"
readonly IMPACT="환경변수 파일의 소유자/권한만 변경되며 서비스 재시작이 불필요함. 다음 로그인 셸 생성 시점부터 반영되고 기존 세션에는 영향이 없음"
readonly SEVERITY="중"
readonly USER_DOTFILES=(.bashrc .bash_profile .bash_login .profile .cshrc .login .kshrc .zshrc)
readonly SYSTEM_FILES=(/etc/profile /etc/bashrc /etc/bash.bashrc /etc/csh.login /etc/csh.cshrc)

CHECK_DETAIL=""

do_check() {
    if [ ! -r /etc/passwd ]; then
        CHECK_DETAIL="/etc/passwd 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    local offenders=() count=0

    while IFS=: read -r uname _ uid _ _ home _; do
        [ -z "$home" ] && continue
        [ -d "$home" ] || continue
        for df in "${USER_DOTFILES[@]}"; do
            local f="${home}/${df}"
            [ -e "$f" ] || continue
            local owner perm
            owner="$(stat -L -c '%U' "$f" 2>/dev/null)"
            perm="$(stat -L -c '%a' "$f" 2>/dev/null)"
            [ -z "$owner" ] || [ -z "$perm" ] && continue
            local perm_last2="${perm: -2}"
            local group="${perm_last2:0:1}" other="${perm_last2:1:1}"
            if { [ "$owner" != "$uname" ] && [ "$owner" != "root" ]; } || [ $(( group & 2 )) -ne 0 ] || [ $(( other & 2 )) -ne 0 ]; then
                count=$((count + 1))
                [ "${#offenders[@]}" -lt 15 ] && offenders+=("${f}(owner=${owner},perm=${perm})")
            fi
        done
    done < /etc/passwd

    for f in "${SYSTEM_FILES[@]}"; do
        [ -e "$f" ] || continue
        local owner perm
        owner="$(stat -L -c '%U' "$f" 2>/dev/null)"
        perm="$(stat -L -c '%a' "$f" 2>/dev/null)"
        [ -z "$owner" ] || [ -z "$perm" ] && continue
        local other="${perm: -1}"
        if [ "$owner" != "root" ] || [ $(( other & 2 )) -ne 0 ]; then
            count=$((count + 1))
            [ "${#offenders[@]}" -lt 15 ] && offenders+=("${f}(owner=${owner},perm=${perm})")
        fi
    done

    if [ "$count" -gt 0 ]; then
        CHECK_DETAIL="소유자/권한이 기준을 벗어난 환경변수 파일 ${count}건(최대 15건 표시) 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="점검된 사용자/시스템 환경변수 파일 모두 소유자 및 권한 기준을 충족함."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
