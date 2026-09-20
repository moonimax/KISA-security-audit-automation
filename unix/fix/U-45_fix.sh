#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-45"
readonly ITEM_TITLE="메일 서비스 버전 점검"
readonly ACTION_TAG="승인요청"
readonly IMPACT="배너 문구 변경 후 메일 서비스 reload 가 필요하며, 반영 중 짧은 순간 신규 연결에 영향을 줄 수 있어 관리자 승인이 필요함"
readonly SEVERITY="하"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    local checked="false" offenders=()
    if [ -r /etc/postfix/main.cf ]; then
        checked="true"
        local banner
        banner="$(grep -E '^[[:space:]]*smtpd_banner[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null | tail -n1)"
        if [ -z "$banner" ] || printf '%s' "$banner" | grep -q '\$mail_version'; then
            offenders+=("/etc/postfix/main.cf(smtpd_banner)")
        fi
    fi
    if [ -r /etc/mail/sendmail.cf ]; then
        checked="true"
        if grep -Eq '^O[[:space:]]*SmtpGreetingMessage=.*\$v' /etc/mail/sendmail.cf 2>/dev/null \
            || ! grep -q 'SmtpGreetingMessage' /etc/mail/sendmail.cf 2>/dev/null; then
            offenders+=("/etc/mail/sendmail.cf(SmtpGreetingMessage)")
        fi
    fi
    if [ "$checked" = "false" ]; then
        CHECK_DETAIL="Postfix, Sendmail 어느 것도 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="SMTP 배너에 버전 정보가 노출될 수 있는 설정 발견: $(IFS='; '; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="설치된 메일 서비스의 SMTP 배너에 버전 정보 노출 설정이 없음."
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 배너 변경 후 서비스 reload 가 필요해 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하세요."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local applied=()

    if [ -w /etc/postfix/main.cf ]; then
        local banner
        banner="$(grep -E '^[[:space:]]*smtpd_banner[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null | tail -n1)"
        if [ -z "$banner" ] || printf '%s' "$banner" | grep -q '\$mail_version'; then
            local backup="/etc/postfix/main.cf.bak.$(date +%Y%m%d%H%M%S)"
            cp -p /etc/postfix/main.cf "$backup" 2>/dev/null
            if grep -qE '^[[:space:]]*smtpd_banner[[:space:]]*=' /etc/postfix/main.cf; then
                sed -i -E 's/^[[:space:]]*smtpd_banner[[:space:]]*=.*/smtpd_banner = $myhostname ESMTP/' /etc/postfix/main.cf
            else
                printf '\nsmtpd_banner = $myhostname ESMTP\n' >> /etc/postfix/main.cf
            fi
            applied+=("/etc/postfix/main.cf smtpd_banner 에서 버전 매크로 제거 (백업: ${backup})")
            restart_active_services postfix || { FIX_DETAIL="postfix 재시작 실패."; return 2; }
        fi
    fi

    if [ -w /etc/mail/sendmail.cf ]; then
        if grep -Eq '^O[[:space:]]*SmtpGreetingMessage=.*\$v' /etc/mail/sendmail.cf 2>/dev/null \
            || ! grep -q 'SmtpGreetingMessage' /etc/mail/sendmail.cf 2>/dev/null; then
            local backup="/etc/mail/sendmail.cf.bak.$(date +%Y%m%d%H%M%S)"
            cp -p /etc/mail/sendmail.cf "$backup" 2>/dev/null
            if grep -qE '^O[[:space:]]*SmtpGreetingMessage=' /etc/mail/sendmail.cf; then
                sed -i -E 's/^O[[:space:]]*SmtpGreetingMessage=.*/O SmtpGreetingMessage=$j Mail Server Ready/' /etc/mail/sendmail.cf
            else
                printf '\nO SmtpGreetingMessage=$j Mail Server Ready\n' >> /etc/mail/sendmail.cf
            fi
            applied+=("/etc/mail/sendmail.cf SmtpGreetingMessage 에서 버전 매크로 제거 (백업: ${backup})")
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
log_info "U-45 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
