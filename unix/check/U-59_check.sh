#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-59"
readonly ITEM_TITLE="안전한 SNMP 버전 사용"
readonly ACTION_TAG="승인요청"
readonly IMPACT="v1/v2c 설정 비활성화 및 v3 사용자 생성은 기존 SNMP 폴링 도구의 인증 방식을 바꾸는 작업으로, 모니터링 시스템 쪽 설정도 함께 변경되어야 하며 snmpd 재시작이 필요해 관리자 승인이 필요함"
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

    local has_v1v2c="false" has_v3="false"
    grep -Eq '^[[:space:]]*(com2sec|rocommunity|rwcommunity)[[:space:]]' "$conf" 2>/dev/null && has_v1v2c="true"
    grep -Eq '^[[:space:]]*createUser[[:space:]]' "$conf" 2>/dev/null && has_v3="true"

    if [ -r /etc/snmp/snmpd.conf.d ]; then
        :
    fi

    if [ "$has_v1v2c" = "true" ]; then
        CHECK_DETAIL="${conf} 에 SNMPv1/v2c community 기반 설정(com2sec/rocommunity/rwcommunity)이 존재함."
        return "$KISA_EXIT_VULN"
    fi

    if [ "$has_v3" = "true" ]; then
        CHECK_DETAIL="${conf} 에 SNMPv1/v2c 설정이 없고 SNMPv3 사용자(createUser)가 구성되어 있음."
        return "$KISA_EXIT_GOOD"
    fi

    CHECK_DETAIL="${conf} 에서 SNMPv1/v2c 설정은 발견되지 않았으나 SNMPv3 사용자 구성도 확인되지 않아 실제 사용 버전을 판단할 수 없음(보수적으로 취약 처리)."
    return "$KISA_EXIT_VULN"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
