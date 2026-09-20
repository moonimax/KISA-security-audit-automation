#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-54"
readonly ITEM_TITLE="암호화되지 않는 FTP 서비스 비활성화"
readonly ACTION_TAG="승인요청"
readonly IMPACT="TLS 강제 설정은 유효한 인증서가 준비되어 있어야 하고 서비스 재시작이 필요하며, 인증서가 없는 상태에서 잘못 적용하면 FTP 서비스 자체가 기동 실패할 수 있어 관리자 승인이 필요함"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

_vsftpd_conf() {
    [ -r /etc/vsftpd.conf ] && { printf '/etc/vsftpd.conf'; return 0; }
    [ -r /etc/vsftpd/vsftpd.conf ] && { printf '/etc/vsftpd/vsftpd.conf'; return 0; }
    return 1
}

_active_ftp_services() {
    local found="" svc
    if command -v systemctl >/dev/null 2>&1; then
        for svc in vsftpd proftpd pure-ftpd wu-ftpd; do systemctl is-active "$svc" >/dev/null 2>&1 && found="${found}${found:+,}$svc"; done
        for svc in ftp.socket vsftpd.socket proftpd.socket; do systemctl is-active "$svc" >/dev/null 2>&1 && found="${found}${found:+,}$svc"; done
    fi
    if grep -Eq '^[[:space:]]*ftp[[:space:]].*[^#]$' /etc/inetd.conf /etc/xinetd.d/* 2>/dev/null; then found="${found}${found:+,}inetd/xinetd-ftp"; fi
    printf '%s' "$found"
}
do_check() {
    local active="$(_active_ftp_services)"
    if [ -n "$active" ]; then CHECK_DETAIL="평문 FTP 서비스 활성: $active. TLS 설정 여부가 아니라 서비스 비활성화 기준으로 취약."; return "$KISA_EXIT_VULN"; fi
    if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq '(^|:)21$'; then
        CHECK_DETAIL="TCP/21 리스너가 있으나 서비스 식별 불가. 평문 FTP 가능성으로 취약."; return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="vsftpd/proftpd/pure-ftpd/inetd FTP 및 TCP/21 리스너가 활성 상태가 아님."; return "$KISA_EXIT_GOOD"
}

do_fix() {
    do_check; local current=$?
    [ "$current" -eq "$KISA_EXIT_GOOD" ] && { FIX_DETAIL="이미 평문 FTP가 비활성 상태."; return 0; }
    [ "$current" -eq "$KISA_EXIT_FAIL" ] && { FIX_DETAIL="점검 실패로 조치 중단."; return 2; }
    if ! is_approved; then FIX_DETAIL="관리자 승인 후 평문 FTP 서비스를 중지·비활성화함."; return 1; fi
    require_root || { FIX_DETAIL="root 권한 필요."; return 2; }
    command -v systemctl >/dev/null 2>&1 || { FIX_DETAIL="systemctl이 없어 자동 비활성화 불가."; return 1; }
    local svc stopped="" failed=""
    for svc in vsftpd proftpd pure-ftpd wu-ftpd ftp.socket vsftpd.socket proftpd.socket; do
        if systemctl is-active "$svc" >/dev/null 2>&1; then
            if systemctl disable --now "$svc" >/dev/null 2>&1; then stopped="${stopped}${stopped:+,}$svc"; else failed="${failed}${failed:+,}$svc"; fi
        fi
    done
    if grep -Eq '^[[:space:]]*ftp[[:space:]]' /etc/inetd.conf /etc/xinetd.d/* 2>/dev/null; then
        FIX_DETAIL="부분 조치/수동 조치 필요: systemd FTP 중지=${stopped:-없음}, inetd/xinetd FTP 설정은 서비스별 검토 후 비활성화 필요."
        return 1
    fi
    [ -z "$failed" ] || { FIX_DETAIL="FTP 서비스 비활성화 실패: $failed."; return 2; }
    FIX_DETAIL="평문 FTP 서비스 중지·비활성화 완료: ${stopped:-대상 없음}."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-54 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
