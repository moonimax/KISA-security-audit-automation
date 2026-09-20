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

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
