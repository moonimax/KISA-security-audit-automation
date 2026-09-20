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

do_check() {
    local checked="false" offenders=()

    if [ -r /etc/postfix/main.cf ]; then
        checked="true"
        local banner
        banner="$(grep -E '^[[:space:]]*smtpd_banner[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null | tail -n1)"
        if [ -z "$banner" ] || printf '%s' "$banner" | grep -q '\$mail_version'; then
            offenders+=("/etc/postfix/main.cf(smtpd_banner 에 \$mail_version 포함 또는 미설정으로 기본값 사용)")
        fi
    fi

    if [ -r /etc/mail/sendmail.cf ]; then
        checked="true"
        if grep -Eq '^O[[:space:]]*SmtpGreetingMessage=.*\$v' /etc/mail/sendmail.cf 2>/dev/null \
            || ! grep -q 'SmtpGreetingMessage' /etc/mail/sendmail.cf 2>/dev/null; then
            offenders+=("/etc/mail/sendmail.cf(SmtpGreetingMessage 에 버전 매크로 \$v 포함 또는 미설정)")
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

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
