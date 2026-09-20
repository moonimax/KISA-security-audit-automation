#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-52"
readonly ITEM_TITLE="Telnet 서비스 비활성화"
readonly ACTION_TAG="승인요청"
readonly IMPACT="서비스 중지(stop/disable)를 수반하는 변경으로, telnet 으로만 접속 가능한 레거시 관리 경로가 남아있다면 관리 접근이 끊길 수 있어 관리자 승인이 필요함"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    local evidences=()
    if [ -f /etc/xinetd.d/telnet ] && ! grep -qE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' /etc/xinetd.d/telnet 2>/dev/null; then
        evidences+=("/etc/xinetd.d/telnet 활성화됨")
    fi
    if [ -r /etc/inetd.conf ] && grep -Eq '^[[:space:]]*telnet[[:space:]]' /etc/inetd.conf 2>/dev/null; then
        evidences+=("/etc/inetd.conf 에 telnet 활성 라인 존재")
    fi
    if command -v systemctl >/dev/null 2>&1; then
        for svc in telnet.socket telnet.service; do
            systemctl is-active "$svc" >/dev/null 2>&1 && evidences+=("systemd 서비스 ${svc} 활성")
        done
    fi
    if command -v pgrep >/dev/null 2>&1 && pgrep -x 'telnetd|in.telnetd' >/dev/null 2>&1; then
        evidences+=("telnetd 프로세스 실행 중")
    fi
    if [ "${#evidences[@]}" -gt 0 ]; then
        CHECK_DETAIL="Telnet 서비스가 활성화되어 있음: $(IFS='; '; echo "${evidences[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="Telnet 서비스가 비활성화되어 있거나 설치되어 있지 않음."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
