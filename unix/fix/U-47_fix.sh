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
FIX_DETAIL=""

do_check() {
    local checked="false" offenders=()
    if [ -r /etc/postfix/main.cf ]; then
        checked="true"
        grep -Eq '^[[:space:]]*mynetworks[[:space:]]*=.*0\.0\.0\.0/0' /etc/postfix/main.cf 2>/dev/null \
            && offenders+=("/etc/postfix/main.cf(mynetworks)")
        grep -Eq 'reject_unauth_destination' /etc/postfix/main.cf 2>/dev/null \
            || offenders+=("/etc/postfix/main.cf(reject_unauth_destination 미설정)")
    fi
    if [ -r /etc/mail/access ]; then
        checked="true"
        grep -Eq '^[[:space:]]*(Connect|All)[[:space:]]*:.*RELAY' /etc/mail/access 2>/dev/null && offenders+=("/etc/mail/access")
    fi
    if [ -r /etc/mail/relay-domains ]; then
        checked="true"
        grep -Eq '^\*$' /etc/mail/relay-domains 2>/dev/null && offenders+=("/etc/mail/relay-domains")
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 릴레이 제한은 서비스 재시작 및 내부 릴레이 대역 판단이 필요해 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하세요(mynetworks 를 좁히려면 KISA_U47_TRUSTED_NETWORKS 도 함께 지정)."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local applied=() manual_notes=()

    if [ -w /etc/postfix/main.cf ]; then
        local backup="/etc/postfix/main.cf.bak.$(date +%Y%m%d%H%M%S)"
        cp -p /etc/postfix/main.cf "$backup" 2>/dev/null
        local changed="false"

        if ! grep -Eq 'reject_unauth_destination' /etc/postfix/main.cf; then
            printf '\nsmtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination\n' >> /etc/postfix/main.cf
            changed="true"
        fi

        if grep -Eq '^[[:space:]]*mynetworks[[:space:]]*=.*0\.0\.0\.0/0' /etc/postfix/main.cf; then
            if [ -n "${KISA_U47_TRUSTED_NETWORKS:-}" ]; then
                local nets
                nets="$(printf '%s' "$KISA_U47_TRUSTED_NETWORKS" | tr ',' ' ')"
                sed -i -E "s/^([[:space:]]*mynetworks[[:space:]]*=).*/\1 127.0.0.0\/8 [::1]\/128 ${nets}/" /etc/postfix/main.cf
                applied+=("mynetworks 를 '${nets}' 로 제한")
                changed="true"
            else
                manual_notes+=("mynetworks 의 0.0.0.0/0 은 KISA_U47_TRUSTED_NETWORKS 미지정으로 변경하지 않음(수동 조치 필요)")
            fi
        fi

        if [ "$changed" = "true" ]; then
            applied+=("/etc/postfix/main.cf 에 reject_unauth_destination 추가 (백업: ${backup})")
            if command -v systemctl >/dev/null 2>&1 && systemctl is-active postfix >/dev/null 2>&1; then systemctl restart postfix >/dev/null 2>&1 || { FIX_DETAIL="postfix 재시작 실패."; return 2; }; fi
        fi
    fi

    if [ -r /etc/mail/access ] && grep -Eq '^[[:space:]]*(Connect|All)[[:space:]]*:.*RELAY' /etc/mail/access 2>/dev/null; then
        manual_notes+=("/etc/mail/access 의 전체 RELAY 허용 규칙은 makemap 재빌드가 필요해 자동 수정 대상에서 제외됨(수동 조치 필요)")
    fi
    if [ -r /etc/mail/relay-domains ] && grep -Eq '^\*$' /etc/mail/relay-domains 2>/dev/null; then
        manual_notes+=("/etc/mail/relay-domains 의 와일드카드 허용은 수동 조치 필요")
    fi

    if [ "${#applied[@]}" -eq 0 ] && [ "${#manual_notes[@]}" -eq 0 ]; then
        FIX_DETAIL="조치 대상을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi

    local parts=()
    [ "${#applied[@]}" -gt 0 ] && parts+=("$(IFS='; '; echo "${applied[*]}")")
    [ "${#manual_notes[@]}" -gt 0 ] && parts+=("$(IFS='; '; echo "${manual_notes[*]}")")
    FIX_DETAIL="$(IFS='; '; echo "${parts[*]}")"

    [ "${#applied[@]}" -eq 0 ] && return 1
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-47 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
