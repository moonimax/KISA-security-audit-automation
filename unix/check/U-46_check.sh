#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-46"
readonly ITEM_TITLE="일반 사용자의 메일 서비스 실행 방지"
readonly ACTION_TAG="승인요청"
readonly IMPACT="sendmail.cf 변경 후 서비스 재시작이 필요하며, 반영 중 메일 처리에 짧은 지연이 발생할 수 있어 관리자 승인이 필요함"
readonly SEVERITY="중"

CHECK_DETAIL=""

do_check() {
    if [ ! -r /etc/mail/sendmail.cf ]; then
        CHECK_DETAIL="Sendmail 이 설치되어 있지 않아 해당 없음(양호). (Postfix 는 postqueue 가 기본적으로 setgid 로 제한되어 있어 별도 대상에서 제외)"
        return "$KISA_EXIT_GOOD"
    fi

    if grep -E '^O[[:space:]]*PrivacyOptions=' /etc/mail/sendmail.cf 2>/dev/null | grep -q 'restrictqrun'; then
        CHECK_DETAIL="sendmail.cf PrivacyOptions 에 restrictqrun 옵션이 설정되어 있어 일반 사용자의 메일 큐 실행이 제한됨."
        return "$KISA_EXIT_GOOD"
    fi

    CHECK_DETAIL="sendmail.cf PrivacyOptions 에 restrictqrun 옵션이 없어 일반 사용자가 메일 큐를 강제 실행할 수 있음."
    return "$KISA_EXIT_VULN"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
