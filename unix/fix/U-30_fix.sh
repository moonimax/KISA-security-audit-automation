#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-30"
readonly ITEM_TITLE="UMASK 설정 관리"
readonly ACTION_TAG="자동조치"
readonly IMPACT="설정 파일 값만 변경되며 서비스 재시작이 불필요함. 이미 로그인된 세션의 UMASK 는 바뀌지 않고, 신규 세션/프로세스부터 적용됨"
readonly SEVERITY="중"
readonly SECURE_UMASK="022"
readonly UMASK_PROFILE_D="/etc/profile.d/99-kisa-umask.sh"
readonly LOGIN_DEFS="/etc/login.defs"

CHECK_DETAIL=""
FIX_DETAIL=""

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

    local applied=()

    if [ -d /etc/profile.d ]; then
        {
            printf '# KISA U-30: 기본 UMASK 설정 (자동조치 스크립트가 생성)\n'
            printf 'umask %s\n' "$SECURE_UMASK"
        } > "$UMASK_PROFILE_D" 2>/dev/null
        if [ -s "$UMASK_PROFILE_D" ]; then
            chmod 644 "$UMASK_PROFILE_D" 2>/dev/null
            applied+=("${UMASK_PROFILE_D} 생성(umask ${SECURE_UMASK})")
        fi
    fi

    if [ -w "$LOGIN_DEFS" ]; then
        local backup="${LOGIN_DEFS}.bak.$(date +%Y%m%d%H%M%S)"
        cp -p "$LOGIN_DEFS" "$backup" 2>/dev/null
        if grep -qE '^[[:space:]]*UMASK[[:space:]]' "$LOGIN_DEFS"; then
            sed -i -E "s/^[[:space:]]*UMASK[[:space:]]+.*/UMASK           ${SECURE_UMASK}/" "$LOGIN_DEFS"
        else
            printf '\nUMASK           %s\n' "$SECURE_UMASK" >> "$LOGIN_DEFS"
        fi
        applied+=("${LOGIN_DEFS} UMASK=${SECURE_UMASK} (백업: ${backup})")
    fi

    if [ "${#applied[@]}" -eq 0 ]; then
        FIX_DETAIL="/etc/profile.d 및 ${LOGIN_DEFS} 어디에도 쓸 수 없어 조치를 수행하지 못함."
        return 2
    fi

    FIX_DETAIL="$(IFS='; '; echo "${applied[*]}")"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-30 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
