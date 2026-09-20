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
FIX_DETAIL=""

do_check() {
    if [ ! -r /etc/mail/sendmail.cf ]; then
        CHECK_DETAIL="Sendmail 이 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    if grep -E '^O[[:space:]]*PrivacyOptions=' /etc/mail/sendmail.cf 2>/dev/null | grep -q 'restrictqrun'; then
        CHECK_DETAIL="sendmail.cf PrivacyOptions 에 restrictqrun 옵션이 설정되어 있음."
        return "$KISA_EXIT_GOOD"
    fi
    CHECK_DETAIL="sendmail.cf PrivacyOptions 에 restrictqrun 옵션이 없음."
    return "$KISA_EXIT_VULN"
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
    if [ ! -w /etc/mail/sendmail.cf ]; then
        FIX_DETAIL="/etc/mail/sendmail.cf 에 쓰기 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local backup="/etc/mail/sendmail.cf.bak.$(date +%Y%m%d%H%M%S)"
    cp -p /etc/mail/sendmail.cf "$backup" 2>/dev/null

    if grep -qE '^O[[:space:]]*PrivacyOptions=' /etc/mail/sendmail.cf; then
        sed -i -E '/^O[[:space:]]*PrivacyOptions=/ s/$/,restrictqrun/' /etc/mail/sendmail.cf
    else
        printf '\nO PrivacyOptions=restrictqrun\n' >> /etc/mail/sendmail.cf
    fi

    restart_active_services sendmail || { FIX_DETAIL="sendmail 재시작 실패."; return 2; }

    FIX_DETAIL="sendmail.cf PrivacyOptions 에 restrictqrun 옵션을 추가함(백업: ${backup})."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-46 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
