#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-61"
readonly ITEM_TITLE="SNMP Access Control 설정"
readonly ACTION_TAG="승인요청"
readonly IMPACT="접근 허용 소스를 좁히면 기존 모니터링 서버의 폴링이 차단될 수 있고 snmpd 재시작이 필요해 관리자 승인이 필요함"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

_find_snmpd_conf() {
    for f in /etc/snmp/snmpd.conf /etc/snmpd.conf; do
        [ -r "$f" ] && { printf '%s' "$f"; return 0; }
    done
    return 1
}

do_check() {
    local conf
    conf="$(_find_snmpd_conf)" || {
        CHECK_DETAIL="snmpd 설정 파일을 찾을 수 없어 SNMP 미사용으로 판단됨. 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    }
    local lines
    lines="$(grep -E '^[[:space:]]*(rocommunity|rwcommunity)[[:space:]]' "$conf" 2>/dev/null)"
    lines="${lines}$(printf '\n')$(grep -E '^[[:space:]]*com2sec[[:space:]]' "$conf" 2>/dev/null)"
    if [ -z "$(printf '%s' "$lines" | tr -d '[:space:]')" ]; then
        CHECK_DETAIL="${conf} 에 SNMPv1/v2c community 기반 설정이 없어 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    local offenders=()
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local source_field
        source_field="$(awk '{print $3}' <<< "$line")"
        if [ -z "$source_field" ] || printf '%s' "$source_field" | grep -qiE '^(default|0\.0\.0\.0/0|any)$'; then
            offenders+=("$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//')")
        fi
    done <<< "$lines"
    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="소스 제한 없이 전체 허용된 SNMP 접근 설정 발견: $(IFS='; '; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="${conf} 의 모든 community 설정에 소스 제한이 지정되어 있음."
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 접근 허용 소스 제한 및 snmpd 재시작이 필요해 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 와 KISA_U61_ALLOWED_SOURCE(허용할 대역, 예: 10.0.0.0/24)를 함께 지정해 재실행하세요."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi
    if [ -z "${KISA_U61_ALLOWED_SOURCE:-}" ]; then
        FIX_DETAIL="승인은 되었으나 KISA_U61_ALLOWED_SOURCE 가 지정되지 않아 조치를 보류함(정상 모니터링 서버가 차단되는 위험을 피하기 위한 안전장치)."
        return 1
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

    sed -i -E "s/^([[:space:]]*(rocommunity|rwcommunity)[[:space:]]+[^[:space:]]+)([[:space:]]+(default|0\.0\.0\.0\/0|any))?[[:space:]]*$/\1 ${KISA_U61_ALLOWED_SOURCE}/I" "$conf"
    sed -i -E "s/^([[:space:]]*com2sec[[:space:]]+[^[:space:]]+[[:space:]]+)(default|0\.0\.0\.0\/0|any)([[:space:]]+[^[:space:]]+)$/\1${KISA_U61_ALLOWED_SOURCE}\3/I" "$conf"

    if command -v systemctl >/dev/null 2>&1 && systemctl is-active snmpd >/dev/null 2>&1; then systemctl restart snmpd >/dev/null 2>&1 || { FIX_DETAIL="snmpd 재시작 실패."; return 2; }; fi

    FIX_DETAIL="${conf} 의 전체 허용 SNMP community 설정을 소스 '${KISA_U61_ALLOWED_SOURCE}' 로 제한함(백업: ${backup})."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-61 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
