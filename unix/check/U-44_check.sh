#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-44"
readonly ITEM_TITLE="tftp, talk 서비스 비활성화"
readonly ACTION_TAG="승인요청"
readonly IMPACT="서비스 중지(stop/disable)를 수반하는 변경으로, 네트워크 장비 펌웨어 배포 등에 tftp 를 실제로 사용 중인 환경이라면 즉시 영향을 받을 수 있어 관리자 승인이 필요함"
readonly SEVERITY="중"
readonly TARGET_SERVICES=(tftp talk ntalk)

CHECK_DETAIL=""

do_check() {
    local evidences=()
    for svc in "${TARGET_SERVICES[@]}"; do
        local f="/etc/xinetd.d/${svc}"
        if [ -f "$f" ] && ! grep -qE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$f" 2>/dev/null; then
            evidences+=("${f} 활성화됨")
        fi
    done
    if [ -r /etc/inetd.conf ]; then
        for svc in "${TARGET_SERVICES[@]}"; do
            grep -Eq "^[[:space:]]*${svc}[[:space:]]" /etc/inetd.conf 2>/dev/null && evidences+=("/etc/inetd.conf 에 ${svc} 활성 라인 존재")
        done
    fi
    if command -v systemctl >/dev/null 2>&1; then
        for svc in tftp.service tftp.socket talk.service ntalk.service; do
            systemctl is-active "$svc" >/dev/null 2>&1 && evidences+=("systemd 서비스 ${svc} 활성")
        done
    fi
    if [ "${#evidences[@]}" -gt 0 ]; then
        CHECK_DETAIL="tftp/talk 서비스가 활성화되어 있음: $(IFS='; '; echo "${evidences[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="tftp/talk/ntalk 서비스가 비활성화되어 있거나 설치되어 있지 않음."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
