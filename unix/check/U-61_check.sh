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
        CHECK_DETAIL="${conf} 에 SNMPv1/v2c community 기반 설정이 없어 해당 없음(양호, SNMPv3 사용 여부는 U-59 참조)."
        return "$KISA_EXIT_GOOD"
    fi

    local offenders=()
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local source_field=""
        if printf '%s' "$line" | grep -qE '^[[:space:]]*com2sec[[:space:]]'; then
            source_field="$(awk '{print $3}' <<< "$line")"
        else
            source_field="$(awk '{print $3}' <<< "$line")"
        fi
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

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
