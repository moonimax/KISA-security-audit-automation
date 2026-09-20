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
FIX_DETAIL=""

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

do_fix() {
    do_check
    local current=$?

    if [ "$current" -eq "$KISA_EXIT_GOOD" ]; then
        FIX_DETAIL="이미 양호 상태로 조치가 필요하지 않음."
        return 0
    fi
    if [ "$current" -eq "$KISA_EXIT_FAIL" ]; then
        FIX_DETAIL="조치 대상 상태를 확인할 수 없어 조치를 수행하지 않음."
        return 2
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local fixed=0 failed=0

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
                if chown "$uname" "$f" 2>/dev/null && chmod go-w "$f" 2>/dev/null; then
                    fixed=$((fixed + 1))
                else
                    failed=$((failed + 1))
                fi
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
            if chown root:root "$f" 2>/dev/null && chmod o-w "$f" 2>/dev/null; then
                fixed=$((fixed + 1))
            else
                failed=$((failed + 1))
            fi
        fi
    done

    log_info "환경변수 파일 권한 조치: 성공 ${fixed}건, 실패 ${failed}건"

    if [ "$fixed" -eq 0 ] && [ "$failed" -eq 0 ]; then
        FIX_DETAIL="조치 대상 파일을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi
    if [ "$failed" -gt 0 ] && [ "$fixed" -eq 0 ]; then
        FIX_DETAIL="환경변수 파일 권한 조치에 모두 실패함(${failed}건)."
        return 2
    fi

    FIX_DETAIL="환경변수 파일 ${fixed}건의 소유자/권한을 보정함(실패 ${failed}건)."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-24 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
