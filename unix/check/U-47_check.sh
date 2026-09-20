#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-47"
readonly ITEM_TITLE="스팸 메일 릴레이 제한"
readonly ACTION_TAG="승인요청"
readonly IMPACT="릴레이 제한 설정 변경 후 메일 서비스 재시작이 필요하며, 정상적으로 릴레이를 허용받던 내부 시스템(그룹웨어 알림 서버 등)이 있다면 즉시 메일 발송이 막힐 수 있어 관리자 승인이 필요함"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    local checked="false" offenders=()

    if [ -r /etc/postfix/main.cf ]; then
        checked="true"
        if grep -Eq '^[[:space:]]*mynetworks[[:space:]]*=.*0\.0\.0\.0/0' /etc/postfix/main.cf 2>/dev/null; then
            offenders+=("/etc/postfix/main.cf(mynetworks 에 0.0.0.0/0 포함)")
        fi
        if ! grep -Eq 'reject_unauth_destination' /etc/postfix/main.cf 2>/dev/null; then
            offenders+=("/etc/postfix/main.cf(reject_unauth_destination 미설정)")
        fi
    fi

    if [ -r /etc/mail/access ]; then
        checked="true"
        grep -Eq '^[[:space:]]*(Connect|All)[[:space:]]*:.*RELAY' /etc/mail/access 2>/dev/null \
            && offenders+=("/etc/mail/access(전체 RELAY 허용 규칙 존재)")
    fi
    if [ -r /etc/mail/relay-domains ]; then
        checked="true"
        grep -Eq '^\*$' /etc/mail/relay-domains 2>/dev/null && offenders+=("/etc/mail/relay-domains(와일드카드 전체 허용)")
    fi

    if [ "$checked" = "false" ]; then
        CHECK_DETAIL="Postfix, Sendmail 어느 것도 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="오픈 릴레이 위험이 있는 설정 발견: $(IFS='; '; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="설치된 메일 서비스에서 오픈 릴레이 위험 설정이 발견되지 않음."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
