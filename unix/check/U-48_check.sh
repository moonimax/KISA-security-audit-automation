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

do_check() {
    local checked="false" offenders=()

    if [ -r /etc/postfix/main.cf ]; then
        checked="true"
        local val
        val="$(grep -E '^[[:space:]]*disable_vrfy_command[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null | tail -n1 | awk -F= '{print tolower($2)}' | tr -d '[:space:]')"
        [ "$val" != "yes" ] && offenders+=("/etc/postfix/main.cf(disable_vrfy_command != yes)")
    fi

    if [ -r /etc/mail/sendmail.cf ]; then
        checked="true"
        local popt
        popt="$(grep -E '^O[[:space:]]*PrivacyOptions=' /etc/mail/sendmail.cf 2>/dev/null | tail -n1)"
        if ! printf '%s' "$popt" | grep -qE 'noexpn|novrfy|goaway'; then
            offenders+=("/etc/mail/sendmail.cf(PrivacyOptions 에 noexpn/novrfy/goaway 없음)")
        fi
    fi

    if [ "$checked" = "false" ]; then
        CHECK_DETAIL="Postfix, Sendmail 어느 것도 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="EXPN/VRFY 명령이 제한되어 있지 않은 설정 발견: $(IFS='; '; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="설치된 메일 서비스에서 EXPN/VRFY 명령이 제한되어 있음."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
