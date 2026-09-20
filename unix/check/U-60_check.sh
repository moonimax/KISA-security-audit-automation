#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-60"
readonly ITEM_TITLE="SNMP Community String 복잡성 설정"
readonly ACTION_TAG="승인요청"
readonly IMPACT="community string 을 변경하면 기존에 이 값으로 폴링하던 모든 모니터링 도구의 설정도 함께 바꿔야 하며, 새 값은 관리자만 알 수 있어 무작위로 자동 생성할 경우 관리자 스스로도 접근할 수 없게 될 위험이 있어 반드시 관리자가 지정한 값으로만 변경함"
readonly SEVERITY="상"
readonly WEAK_RE='^(public|private|community|snmp|admin|snmpd?|test|password|default)$'

CHECK_DETAIL=""

_find_snmpd_conf() {
    for f in /etc/snmp/snmpd.conf /etc/snmpd.conf; do
        [ -r "$f" ] && { printf '%s' "$f"; return 0; }
    done
    return 1
}

_community_is_strong() {
    local c="$1" len="${#1}"
    [[ "$c" =~ [[:alpha:]] ]] && [[ "$c" =~ [[:digit:]] ]] || return 1
    if [ "$len" -ge 10 ] && [[ "$c" =~ ^[[:alnum:]]+$ ]]; then return 0; fi
    if [ "$len" -ge 8 ] && [[ "$c" =~ [^[:alnum:]] ]]; then return 0; fi
    return 1
}
do_check() {
    local conf; conf="$(_find_snmpd_conf)" || { CHECK_DETAIL="snmpd 설정 파일이 없어 해당 없음(양호)."; return "$KISA_EXIT_GOOD"; }
    local communities weak=() c
    communities="$(grep -E '^[[:space:]]*(rocommunity|rwcommunity)[[:space:]]' "$conf" 2>/dev/null | awk '{print $2}')"
    communities="${communities}$(printf '\n')$(grep -E '^[[:space:]]*com2sec[[:space:]]' "$conf" 2>/dev/null | awk '{print $NF}')"
    [ -n "$(printf '%s' "$communities" | tr -d '[:space:]')" ] || { CHECK_DETAIL="$conf에 SNMPv1/v2c community가 없어 해당 없음(양호)."; return "$KISA_EXIT_GOOD"; }
    while IFS= read -r c; do [ -z "$c" ] || _community_is_strong "$c" || weak+=("$c"); done <<< "$communities"
    if [ "${#weak[@]}" -gt 0 ]; then CHECK_DETAIL="복잡성 미충족 community: $(IFS=','; echo "${weak[*]}"). 영문+숫자 10자 또는 영문+숫자+특수문자 8자 이상 필요."; return "$KISA_EXIT_VULN"; fi
    CHECK_DETAIL="모든 community가 길이·조합 복잡성 기준을 충족함."; return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
