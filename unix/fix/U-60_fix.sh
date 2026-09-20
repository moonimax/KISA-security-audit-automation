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
FIX_DETAIL=""

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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): community string 변경은 모니터링 도구 설정과 함께 바뀌어야 하고 snmpd 재시작이 필요해 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 와 KISA_U60_NEW_COMMUNITY(새 community string)를 함께 지정해 재실행하세요."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi
    if [ -z "${KISA_U60_NEW_COMMUNITY:-}" ]; then
        FIX_DETAIL="승인은 되었으나 KISA_U60_NEW_COMMUNITY 가 지정되지 않아 조치를 보류함(관리자가 알지 못하는 값으로 자동 변경되어 접근 불능이 되는 것을 방지하기 위한 안전장치)."
        return 1
    fi
    if ! _community_is_strong "$KISA_U60_NEW_COMMUNITY"; then
        FIX_DETAIL="KISA_U60_NEW_COMMUNITY가 복잡성 기준을 충족하지 않음."
        return 2
    fi

    local conf
    conf="$(_find_snmpd_conf)" || {
        FIX_DETAIL="조치 대상 설정 파일을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    }
    if [ ! -w "$conf" ]; then
        FIX_DETAIL="${conf} 에 쓰기 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local backup="${conf}.bak.$(date +%Y%m%d%H%M%S)"
    cp -p "$conf" "$backup" 2>/dev/null

    sed -i -E "s/^([[:space:]]*(rocommunity|rwcommunity)[[:space:]]+)[^[:space:]]+/\1${KISA_U60_NEW_COMMUNITY}/" "$conf"
    sed -i -E "s/^([[:space:]]*com2sec[[:space:]].*[[:space:]])[^[:space:]]+$/\1${KISA_U60_NEW_COMMUNITY}/" "$conf"

    if command -v systemctl >/dev/null 2>&1 && systemctl is-active snmpd >/dev/null 2>&1; then
        systemctl restart snmpd >/dev/null 2>&1 || { cp -p "$backup" "$conf"; FIX_DETAIL="snmpd 재시작 실패로 설정 롤백."; return 2; }
    fi

    FIX_DETAIL="${conf} 의 community string 을 관리자가 지정한 값으로 교체함(백업: ${backup}). 모니터링 도구 측 설정도 함께 갱신해야 함."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-60 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
