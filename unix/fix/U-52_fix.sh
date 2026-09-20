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
FIX_DETAIL=""

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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 서비스 중지가 필요한 항목이라 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하세요."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local applied=()
    if [ -f /etc/xinetd.d/telnet ] && ! grep -qE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' /etc/xinetd.d/telnet 2>/dev/null; then
        local backup="/etc/xinetd.d/telnet.bak.$(date +%Y%m%d%H%M%S)"
        cp -p /etc/xinetd.d/telnet "$backup" 2>/dev/null
        if grep -qE '^[[:space:]]*disable[[:space:]]*=' /etc/xinetd.d/telnet; then
            sed -i -E 's/^[[:space:]]*disable[[:space:]]*=.*/\tdisable = yes/' /etc/xinetd.d/telnet
        else
            sed -i '/^}/i \\tdisable = yes' /etc/xinetd.d/telnet
        fi
        applied+=("/etc/xinetd.d/telnet disable=yes (백업: ${backup})")
        restart_active_services xinetd || { FIX_DETAIL="xinetd 재시작 실패."; return 2; }
    fi

    if command -v systemctl >/dev/null 2>&1; then
        for svc in telnet.socket telnet.service; do
            if systemctl is-active "$svc" >/dev/null 2>&1; then
                systemctl disable --now "$svc" >/dev/null 2>&1 && applied+=("systemd ${svc} disable --now")
            fi
        done
    fi

    if command -v pgrep >/dev/null 2>&1 && pgrep -x 'telnetd|in.telnetd' >/dev/null 2>&1; then
        pkill -x 'telnetd' 2>/dev/null; pkill -x 'in.telnetd' 2>/dev/null
        applied+=("실행 중이던 telnetd 프로세스 종료")
    fi

    if [ "${#applied[@]}" -eq 0 ]; then
        FIX_DETAIL="조치 대상을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi
    FIX_DETAIL="$(IFS='; '; echo "${applied[*]}")"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-52 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
