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

CHECK_DETAIL=""
CHECK_EVIDENCE=""

do_check() {
    local pam_files=(/etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth /etc/pam.d/login)
    local active_lines="" f
    for f in "${pam_files[@]}"; do
        [ -r "$f" ] || continue
        active_lines="${active_lines}$(printf '\n')$(grep -E '^[[:space:]]*(auth|account)[[:space:]].*pam_(faillock|tally2)\\.so' "$f" 2>/dev/null | grep -v '^[[:space:]]*#')"
    done
    if [ -z "$(printf '%s' "$active_lines" | tr -d '[:space:]')" ]; then
        CHECK_EVIDENCE="$(evidence_json "PAM 잠금 모듈" "연결 안 됨" "잠금 임계값" "설정 안 됨")"
        CHECK_DETAIL="faillock.conf 값과 무관하게 PAM 인증 스택에 pam_faillock/pam_tally2가 연결되어 있지 않아 잠금 정책이 실제 적용되지 않음."
        return "$KISA_EXIT_VULN"
    fi
    local deny_val
    deny_val="$(printf '%s\n' "$active_lines" | grep -oE 'deny[[:space:]]*=[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -n1)"
    if [ -z "$deny_val" ] && printf '%s' "$active_lines" | grep -q 'pam_faillock\\.so' && [ -r /etc/security/faillock.conf ]; then
        deny_val="$(awk -F= '/^[[:space:]]*deny[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/security/faillock.conf)"
    fi
    if ! [[ "$deny_val" =~ ^[0-9]+$ ]] || [ "$deny_val" -lt 1 ] || [ "$deny_val" -gt "$DENY_LIMIT" ]; then
        CHECK_EVIDENCE="$(evidence_json "PAM 잠금 모듈" "연결됨" "잠금 임계값" "${deny_val:-설정 안 됨}" "판정 기준" "${DENY_LIMIT}회 이하")"
        CHECK_DETAIL="PAM 잠금 모듈은 연결되어 있으나 유효 deny=${deny_val:-미설정}로 ${DENY_LIMIT}회 이하 기준을 충족하지 않음."
        return "$KISA_EXIT_VULN"
    fi
    CHECK_EVIDENCE="$(evidence_json "PAM 잠금 모듈" "연결됨" "잠금 임계값" "$deny_val" "판정 기준" "${DENY_LIMIT}회 이하")"
    CHECK_DETAIL="PAM 인증 스택에 잠금 모듈이 실제 연결되어 있고 유효 deny=$deny_val로 기준을 충족함."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY" "$CHECK_EVIDENCE"
