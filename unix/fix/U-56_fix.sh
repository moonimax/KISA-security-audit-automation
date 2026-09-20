#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-56"
readonly ITEM_TITLE="FTP 서비스 접근 제어 설정"
readonly ACTION_TAG="승인요청"
readonly IMPACT="접근 제어 규칙 변경은 정상적인 FTP 클라이언트의 접속을 차단할 위험이 있으며, 허용할 IP 목록은 관리자 판단이 필요해 승인이 필요함"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

_ftp_installed() {
    { [ -r /etc/vsftpd.conf ] || [ -r /etc/vsftpd/vsftpd.conf ] || [ -r /etc/proftpd/proftpd.conf ]; }
}

do_check() {
    if ! _ftp_installed; then
        CHECK_DETAIL="FTP 서비스(vsftpd/proftpd)가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    local evidences=()
    if [ -r /etc/hosts.allow ] && grep -Eq '^(vsftpd|in\.ftpd|proftpd|ftp)' /etc/hosts.allow 2>/dev/null; then
        evidences+=("hosts.allow 에 FTP 관련 제한 설정 존재")
    fi
    if [ -r /etc/hosts.deny ] && grep -Eq '^[[:space:]]*ALL[[:space:]]*:[[:space:]]*ALL' /etc/hosts.deny 2>/dev/null; then
        evidences+=("hosts.deny 에 ALL:ALL 기본 차단 설정")
    fi
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; then
        evidences+=("firewalld 활성")
    fi
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
        evidences+=("ufw 활성")
    fi
    if command -v nft >/dev/null 2>&1 && [ -n "$(nft list ruleset 2>/dev/null)" ]; then
        evidences+=("nftables 규칙 로드됨")
    fi
    if [ "${#evidences[@]}" -gt 0 ]; then
        CHECK_DETAIL="FTP 접근을 제한할 수 있는 메커니즘 확인됨: $(IFS='; '; echo "${evidences[*]}")"
        return "$KISA_EXIT_GOOD"
    fi
    CHECK_DETAIL="FTP 서비스가 설치되어 있으나 TCP Wrappers/방화벽 등 어떤 접근 제어 메커니즘도 확인되지 않음."
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 접근 제어 규칙 변경은 정상 클라이언트를 차단할 위험이 있어 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 와 KISA_U56_ALLOWED_IPS(허용할 IP, 콤마 구분)를 함께 지정해 재실행하세요."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi
    if [ -z "${KISA_U56_ALLOWED_IPS:-}" ]; then
        FIX_DETAIL="승인은 되었으나 KISA_U56_ALLOWED_IPS 가 지정되지 않아 조치를 보류함(정상 FTP 클라이언트 차단 위험을 피하기 위한 안전장치)."
        return 1
    fi

    local allowed_ips
    allowed_ips="$(printf '%s' "$KISA_U56_ALLOWED_IPS" | tr ',' ' ')"

    local backup_allow="/etc/hosts.allow.bak.$(date +%Y%m%d%H%M%S)"
    local backup_deny="/etc/hosts.deny.bak.$(date +%Y%m%d%H%M%S)"
    [ -e /etc/hosts.allow ] && cp -p /etc/hosts.allow "$backup_allow" 2>/dev/null
    [ -e /etc/hosts.deny ] && cp -p /etc/hosts.deny "$backup_deny" 2>/dev/null

    {
        printf '\n# KISA U-56: 자동조치 스크립트가 추가(승인됨)\n'
        printf 'vsftpd: 127.0.0.1 ::1 %s\n' "$allowed_ips"
        printf 'in.ftpd: 127.0.0.1 ::1 %s\n' "$allowed_ips"
    } >> /etc/hosts.allow 2>/dev/null

    if ! grep -qE '^[[:space:]]*ALL[[:space:]]*:[[:space:]]*ALL' /etc/hosts.deny 2>/dev/null; then
        {
            printf '\n# KISA U-56: 자동조치 스크립트가 추가(승인됨)\n'
            printf 'ALL: ALL\n'
        } >> /etc/hosts.deny 2>/dev/null
    fi

    FIX_DETAIL="TCP Wrappers 설정: /etc/hosts.allow 에 vsftpd/in.ftpd 허용 IP(${allowed_ips}, 127.0.0.1, ::1)를 추가하고 /etc/hosts.deny 에 ALL:ALL 을 보장함(백업: ${backup_allow:-없음}, ${backup_deny:-없음})."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-56 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
