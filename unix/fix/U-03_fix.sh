#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-03"
readonly ITEM_TITLE="계정 잠금 임계값 설정"
readonly ACTION_TAG="승인요청"
readonly IMPACT="PAM 인증 스택(faillock/tally2) 설정을 변경하는 항목으로, 값이 잘못 적용될 경우 SSH/콘솔/su 등 모든 로그인 경로가 동시에 잠길 위험이 있어 서비스 영향도가 높음"
readonly SEVERITY="중"
readonly DENY_LIMIT=5
readonly UNLOCK_TIME=120
readonly FAILLOCK_CONF="/etc/security/faillock.conf"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    local pam_files=(/etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth /etc/pam.d/login)
    local active_lines="" f
    for f in "${pam_files[@]}"; do
        [ -r "$f" ] || continue
        active_lines="${active_lines}$(printf '\n')$(grep -E '^[[:space:]]*(auth|account)[[:space:]].*pam_(faillock|tally2)\\.so' "$f" 2>/dev/null | grep -v '^[[:space:]]*#')"
    done
    if [ -z "$(printf '%s' "$active_lines" | tr -d '[:space:]')" ]; then
        CHECK_DETAIL="faillock.conf 값과 무관하게 PAM 인증 스택에 pam_faillock/pam_tally2가 연결되어 있지 않아 잠금 정책이 실제 적용되지 않음."
        return "$KISA_EXIT_VULN"
    fi
    local deny_val
    deny_val="$(printf '%s\n' "$active_lines" | grep -oE 'deny[[:space:]]*=[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -n1)"
    if [ -z "$deny_val" ] && printf '%s' "$active_lines" | grep -q 'pam_faillock\\.so' && [ -r /etc/security/faillock.conf ]; then
        deny_val="$(awk -F= '/^[[:space:]]*deny[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/security/faillock.conf)"
    fi
    if ! [[ "$deny_val" =~ ^[0-9]+$ ]] || [ "$deny_val" -lt 1 ] || [ "$deny_val" -gt "$DENY_LIMIT" ]; then
        CHECK_DETAIL="PAM 잠금 모듈은 연결되어 있으나 유효 deny=${deny_val:-미설정}로 ${DENY_LIMIT}회 이하 기준을 충족하지 않음."
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="PAM 인증 스택에 잠금 모듈이 실제 연결되어 있고 유효 deny=$deny_val로 기준을 충족함."
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

    if [ "$ACTION_TAG" = "승인요청" ] && ! is_approved; then
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): PAM 인증 스택 변경은 전체 로그인 경로에 영향을 주는 고위험 작업이라 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하거나, 수동으로 pam_faillock(또는 pam_tally2) deny=${DENY_LIMIT} 설정 후 신규 세션에서 검증하세요."
        return 1
    fi

    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    if [ -e "$FAILLOCK_CONF" ] || command -v pam_faillock >/dev/null 2>&1 || [ -d /etc/security ]; then
        local backup="${FAILLOCK_CONF}.bak.$(date +%Y%m%d%H%M%S)"
        [ -e "$FAILLOCK_CONF" ] && cp -p "$FAILLOCK_CONF" "$backup" 2>/dev/null

        touch "$FAILLOCK_CONF" 2>/dev/null || { FIX_DETAIL="${FAILLOCK_CONF} 생성 실패로 조치를 중단함."; return 2; }

        if grep -qE '^[[:space:]]*deny[[:space:]]*=' "$FAILLOCK_CONF"; then
            sed -i -E "s/^[[:space:]]*deny[[:space:]]*=.*/deny = ${DENY_LIMIT}/" "$FAILLOCK_CONF"
        else
            printf 'deny = %s\n' "$DENY_LIMIT" >> "$FAILLOCK_CONF"
        fi
        if grep -qE '^[[:space:]]*unlock_time[[:space:]]*=' "$FAILLOCK_CONF"; then
            sed -i -E "s/^[[:space:]]*unlock_time[[:space:]]*=.*/unlock_time = ${UNLOCK_TIME}/" "$FAILLOCK_CONF"
        else
            printf 'unlock_time = %s\n' "$UNLOCK_TIME" >> "$FAILLOCK_CONF"
        fi

        if ! grep -RqsE '^[[:space:]]*(auth|account)[[:space:]].*pam_faillock\.so' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth /etc/pam.d/login 2>/dev/null; then
            FIX_DETAIL="${FAILLOCK_CONF} 값은 적용했으나 PAM 인증 스택에 pam_faillock.so가 연결되어 있지 않음. 부분 조치/수동 조치 필요(로그인 전체 차단 위험 때문에 자동 삽입하지 않음). 백업: ${backup:-없음}"
            return 1
        fi
        FIX_DETAIL="${FAILLOCK_CONF}에 deny=${DENY_LIMIT}, unlock_time=${UNLOCK_TIME}를 적용하고 PAM 스택 연결을 확인함. 백업: ${backup:-없음}"
        return 0
    fi

    FIX_DETAIL="faillock.conf 경로를 생성할 수 없는 환경으로 자동 조치를 수행하지 못함. 수동 조치가 필요함."
    return 2
}

do_fix
KISA_FIX_RC=$?
log_info "U-03 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
