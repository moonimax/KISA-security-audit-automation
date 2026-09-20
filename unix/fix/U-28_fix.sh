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
FIX_DETAIL=""

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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 접근 제어 규칙 변경은 관리자 자신의 세션을 차단할 위험이 있어 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 와 KISA_U28_ALLOWED_IPS(허용할 IP, 콤마 구분)를 함께 지정해 재실행하세요."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    if [ -z "${KISA_U28_ALLOWED_IPS:-}" ]; then
        FIX_DETAIL="승인은 되었으나 KISA_U28_ALLOWED_IPS 가 지정되지 않아 조치를 보류함(관리자 자신을 포함한 전체 접속 차단 위험을 피하기 위한 안전장치). 예: KISA_U28_ALLOWED_IPS='203.0.113.10,203.0.113.0/24' KISA_APPROVAL=true 로 재실행하세요. 방화벽(iptables/nftables/firewalld) 정책은 영향 범위가 더 커 본 스크립트의 자동화 대상에서 제외되며, 관리자가 별도로 검토·적용해야 함."
        return 1
    fi

    local allowed_ips
    allowed_ips="$(printf '%s' "$KISA_U28_ALLOWED_IPS" | tr ',' ' ')"

    local backup_allow="/etc/hosts.allow.bak.$(date +%Y%m%d%H%M%S)"
    local backup_deny="/etc/hosts.deny.bak.$(date +%Y%m%d%H%M%S)"
    [ -e /etc/hosts.allow ] && cp -p /etc/hosts.allow "$backup_allow" 2>/dev/null
    [ -e /etc/hosts.deny ] && cp -p /etc/hosts.deny "$backup_deny" 2>/dev/null

    {
        printf '\n# KISA U-28: 자동조치 스크립트가 추가(승인됨)\n'
        printf 'ALL: 127.0.0.1 ::1 %s\n' "$allowed_ips"
    } >> /etc/hosts.allow 2>/dev/null

    {
        printf '\n# KISA U-28: 자동조치 스크립트가 추가(승인됨)\n'
        printf 'ALL: ALL\n'
    } >> /etc/hosts.deny 2>/dev/null

    if ! grep -q "$allowed_ips" /etc/hosts.allow 2>/dev/null; then
        FIX_DETAIL="hosts.allow/hosts.deny 갱신에 실패함."
        return 2
    fi

    FIX_DETAIL="TCP Wrappers 설정: /etc/hosts.allow 에 허용 IP(${allowed_ips}, 127.0.0.1, ::1)를 추가하고 /etc/hosts.deny 에 ALL:ALL 을 추가함(백업: ${backup_allow:-없음}, ${backup_deny:-없음}). 단, TCP Wrappers 는 libwrap 기반 서비스에만 적용되며 다수의 최신 OpenSSH 빌드는 이를 지원하지 않으므로, 실질적인 접근 제어를 위해서는 방화벽(iptables/nftables/firewalld) 수준의 규칙을 관리자가 별도로 검토·적용해야 함."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-28 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
