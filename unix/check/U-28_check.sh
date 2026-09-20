#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-28"
readonly ITEM_TITLE="접속 IP 및 포트 제한"
readonly ACTION_TAG="승인요청"
readonly IMPACT="TCP Wrappers 또는 방화벽 규칙 변경은 관리자의 현재 SSH 접속 자체를 차단할 수 있는 세션 단절 위험이 있으며, 어떤 IP/포트를 허용할지는 서비스 운영 정책에 대한 관리자 판단이 반드시 필요함"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    local evidences=()

    if [ -r /etc/hosts.deny ] && grep -Eq '^[[:space:]]*ALL[[:space:]]*:[[:space:]]*ALL' /etc/hosts.deny 2>/dev/null; then
        evidences+=("hosts.deny에 ALL:ALL 차단 설정")
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

    if command -v iptables >/dev/null 2>&1; then
        local input_policy rule_count
        input_policy="$(iptables -S INPUT 2>/dev/null | awk '/^-P INPUT/{print $3; exit}')"
        rule_count="$(iptables -S INPUT 2>/dev/null | grep -c '^-A')"
        if [ "$input_policy" = "DROP" ] || [ "$input_policy" = "REJECT" ] || [ "${rule_count:-0}" -gt 0 ]; then
            evidences+=("iptables INPUT policy=${input_policy:-알수없음}, 규칙 ${rule_count:-0}건")
        fi
    fi

    if [ "${#evidences[@]}" -gt 0 ]; then
        CHECK_DETAIL="접속 제어 메커니즘 확인됨: $(IFS='; '; echo "${evidences[*]}")"
        return "$KISA_EXIT_GOOD"
    fi

    CHECK_DETAIL="TCP Wrappers(hosts.deny), firewalld, ufw, nftables, iptables 어디에서도 유의미한 접속 제한 설정을 확인하지 못함."
    return "$KISA_EXIT_VULN"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
