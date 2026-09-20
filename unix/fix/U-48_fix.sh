#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-48"
readonly ITEM_TITLE="expn, vrfy 명령어 제한"
readonly ACTION_TAG="승인요청"
readonly IMPACT="설정 변경 후 메일 서비스 재시작이 필요해 관리자 승인이 필요함"
readonly SEVERITY="중"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    local checked="false" offenders=()
    if [ -r /etc/postfix/main.cf ]; then
        checked="true"
        local val
        val="$(grep -E '^[[:space:]]*disable_vrfy_command[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null | tail -n1 | awk -F= '{print tolower($2)}' | tr -d '[:space:]')"
        [ "$val" != "yes" ] && offenders+=("/etc/postfix/main.cf")
    fi
    if [ -r /etc/mail/sendmail.cf ]; then
        checked="true"
        local popt
        popt="$(grep -E '^O[[:space:]]*PrivacyOptions=' /etc/mail/sendmail.cf 2>/dev/null | tail -n1)"
        printf '%s' "$popt" | grep -qE 'noexpn|novrfy|goaway' || offenders+=("/etc/mail/sendmail.cf")
    fi
    if [ "$checked" = "false" ]; then
        CHECK_DETAIL="Postfix, Sendmail 어느 것도 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="EXPN/VRFY 명령이 제한되어 있지 않은 설정 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="설치된 메일 서비스에서 EXPN/VRFY 명령이 제한되어 있음."
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 서비스 재시작이 필요한 항목이라 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하세요."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local applied=()

    if [ -w /etc/postfix/main.cf ]; then
        local val
        val="$(grep -E '^[[:space:]]*disable_vrfy_command[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null | tail -n1 | awk -F= '{print tolower($2)}' | tr -d '[:space:]')"
        if [ "$val" != "yes" ]; then
            local backup="/etc/postfix/main.cf.bak.$(date +%Y%m%d%H%M%S)"
            cp -p /etc/postfix/main.cf "$backup" 2>/dev/null
            if grep -qE '^[[:space:]]*disable_vrfy_command[[:space:]]*=' /etc/postfix/main.cf; then
                sed -i -E 's/^[[:space:]]*disable_vrfy_command[[:space:]]*=.*/disable_vrfy_command = yes/' /etc/postfix/main.cf
            else
                printf '\ndisable_vrfy_command = yes\n' >> /etc/postfix/main.cf
            fi
            applied+=("/etc/postfix/main.cf disable_vrfy_command=yes (백업: ${backup})")
            restart_active_services postfix || { FIX_DETAIL="postfix 재시작 실패."; return 2; }
        fi
    fi

    if [ -w /etc/mail/sendmail.cf ]; then
        local popt
        popt="$(grep -E '^O[[:space:]]*PrivacyOptions=' /etc/mail/sendmail.cf 2>/dev/null | tail -n1)"
        if ! printf '%s' "$popt" | grep -qE 'noexpn|novrfy|goaway'; then
            local backup="/etc/mail/sendmail.cf.bak.$(date +%Y%m%d%H%M%S)"
            cp -p /etc/mail/sendmail.cf "$backup" 2>/dev/null
            if grep -qE '^O[[:space:]]*PrivacyOptions=' /etc/mail/sendmail.cf; then
                sed -i -E '/^O[[:space:]]*PrivacyOptions=/ s/$/,noexpn,novrfy/' /etc/mail/sendmail.cf
            else
                printf '\nO PrivacyOptions=noexpn,novrfy\n' >> /etc/mail/sendmail.cf
            fi
            applied+=("/etc/mail/sendmail.cf PrivacyOptions 에 noexpn,novrfy 추가 (백업: ${backup})")
            restart_active_services sendmail || { FIX_DETAIL="sendmail 재시작 실패."; return 2; }
        fi
    fi

    if [ "${#applied[@]}" -eq 0 ]; then
        FIX_DETAIL="조치 대상 설정 파일에 쓰기 권한이 없거나 대상을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 2
    fi
    FIX_DETAIL="$(IFS='; '; echo "${applied[*]}")"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-48 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
