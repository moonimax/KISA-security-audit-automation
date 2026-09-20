#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-11"
readonly ITEM_TITLE="사용자 shell 점검"
readonly ACTION_TAG="자동조치"
readonly IMPACT="대상 계정의 로그인 셸만 nologin으로 변경되며 서비스 재시작이 불필요함. usermod -s 로 즉시 되돌릴 수 있는 가역적 변경이나, 극히 일부 특수 목적 서비스 계정이 셸 실행을 필요로 하는 경우 영향이 있을 수 있음"
readonly SEVERITY="하"
readonly LOGIN_DEFS="/etc/login.defs"
readonly NONINTERACTIVE_RE='(nologin|false|sync|halt|shutdown|true)$'

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    if [ ! -r /etc/passwd ]; then
        CHECK_DETAIL="/etc/passwd 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    local sys_min sys_max
    sys_min="$(awk '/^[[:space:]]*SYS_UID_MIN[[:space:]]/{print $2; exit}' "$LOGIN_DEFS" 2>/dev/null)"
    sys_max="$(awk '/^[[:space:]]*SYS_UID_MAX[[:space:]]/{print $2; exit}' "$LOGIN_DEFS" 2>/dev/null)"
    sys_min="${sys_min:-1}"
    sys_max="${sys_max:-999}"

    local offenders
    offenders="$(awk -F: -v lo="$sys_min" -v hi="$sys_max" \
        '$3>=lo && $3<=hi && $3!=0 {print $1":"$7}' /etc/passwd \
        | grep -vE ":(.*/)?${NONINTERACTIVE_RE}" \
        | awk -F: '{print $1}' | tr '\n' ',' | sed 's/,$//')"

    if [ -n "$offenders" ]; then
        CHECK_DETAIL="대화형 로그인 셸이 부여된 시스템 계정(UID ${sys_min}~${sys_max}) 발견: ${offenders}"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="UID ${sys_min}~${sys_max} 범위의 시스템 계정은 모두 비대화형 셸을 사용 중임."
    return "$KISA_EXIT_GOOD"
}

_resolve_nologin_shell() {
    for s in /usr/sbin/nologin /sbin/nologin /bin/false; do
        [ -x "$s" ] && { printf '%s' "$s"; return 0; }
    done
    return 1
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
    if ! command -v usermod >/dev/null 2>&1; then
        FIX_DETAIL="usermod 명령을 찾을 수 없어 조치를 수행할 수 없음."
        return 2
    fi

    local nologin_shell
    nologin_shell="$(_resolve_nologin_shell)" || {
        FIX_DETAIL="사용 가능한 nologin 셸(/usr/sbin/nologin, /sbin/nologin, /bin/false)을 찾을 수 없어 조치를 수행할 수 없음."
        return 2
    }

    local sys_min sys_max
    sys_min="$(awk '/^[[:space:]]*SYS_UID_MIN[[:space:]]/{print $2; exit}' "$LOGIN_DEFS" 2>/dev/null)"
    sys_max="$(awk '/^[[:space:]]*SYS_UID_MAX[[:space:]]/{print $2; exit}' "$LOGIN_DEFS" 2>/dev/null)"
    sys_min="${sys_min:-1}"
    sys_max="${sys_max:-999}"

    local offenders
    offenders="$(awk -F: -v lo="$sys_min" -v hi="$sys_max" \
        '$3>=lo && $3<=hi && $3!=0 {print $1":"$7}' /etc/passwd \
        | grep -vE ":(.*/)?${NONINTERACTIVE_RE}" \
        | awk -F: '{print $1}')"

    if [ -z "$offenders" ]; then
        FIX_DETAIL="조치 대상 계정을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi

    local backup="/etc/passwd.bak.$(date +%Y%m%d%H%M%S)"
    cp -p /etc/passwd "$backup" 2>/dev/null
    log_info "/etc/passwd 백업 완료: ${backup}"

    local changed_list="" failed_list=""
    while IFS= read -r acct; do
        [ -z "$acct" ] && continue
        if usermod -s "$nologin_shell" "$acct" 2>/dev/null; then
            log_info "계정 ${acct} 셸을 ${nologin_shell} 로 변경함."
            changed_list="${changed_list}${changed_list:+,}${acct}"
        else
            log_error "계정 ${acct} 셸 변경 실패."
            failed_list="${failed_list}${failed_list:+,}${acct}"
        fi
    done <<< "$offenders"

    if [ -n "$failed_list" ]; then
        FIX_DETAIL="셸 변경 실패 계정: ${failed_list}. 성공: ${changed_list:-없음}. 백업: ${backup}"
        return 2
    fi

    FIX_DETAIL="시스템 계정(${changed_list})의 로그인 셸을 ${nologin_shell} 로 변경함. 백업: ${backup}"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-11 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
