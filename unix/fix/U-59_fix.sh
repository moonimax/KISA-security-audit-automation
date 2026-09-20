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
    local has_v1v2c="false" has_v3="false"
    grep -Eq '^[[:space:]]*(com2sec|rocommunity|rwcommunity)[[:space:]]' "$conf" 2>/dev/null && has_v1v2c="true"
    grep -Eq '^[[:space:]]*createUser[[:space:]]' "$conf" 2>/dev/null && has_v3="true"
    if [ "$has_v1v2c" = "true" ]; then
        CHECK_DETAIL="${conf} 에 SNMPv1/v2c community 기반 설정이 존재함."
        return "$KISA_EXIT_VULN"
    fi
    if [ "$has_v3" = "true" ]; then
        CHECK_DETAIL="${conf} 에 SNMPv1/v2c 설정이 없고 SNMPv3 사용자가 구성되어 있음."
        return "$KISA_EXIT_GOOD"
    fi
    CHECK_DETAIL="${conf} 에서 SNMPv1/v2c 설정은 없으나 SNMPv3 사용자 구성도 없어 취약으로 판단."
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): SNMPv3 전환은 모니터링 도구 설정 변경 및 snmpd 재시작이 필요해 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 와 KISA_U59_V3_USER/KISA_U59_V3_AUTHPASS/KISA_U59_V3_PRIVPASS 를 함께 지정해 재실행하세요."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi
    if [ -z "${KISA_U59_V3_USER:-}" ] || [ -z "${KISA_U59_V3_AUTHPASS:-}" ] || [ -z "${KISA_U59_V3_PRIVPASS:-}" ]; then
        FIX_DETAIL="승인은 되었으나 KISA_U59_V3_USER/AUTHPASS/PRIVPASS 가 모두 지정되지 않아 조치를 보류함(v3 자격증명 없이 v1/v2c 만 끄면 모니터링이 완전히 끊어지는 것을 방지하기 위한 안전장치)."
        return 1
    fi
    if [ "${#KISA_U59_V3_AUTHPASS}" -lt 8 ] || [ "${#KISA_U59_V3_PRIVPASS}" -lt 8 ]; then
        FIX_DETAIL="SNMPv3 인증/개인정보 보호 암호는 8자 이상이어야 하는 프로토콜 제약이 있어 조치를 보류함."
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

    sed -i -E 's/^([[:space:]]*(com2sec|rocommunity|rwcommunity)[[:space:]])/#\1/' "$conf"

    {
        printf '\n# KISA U-59: SNMPv3 사용자 (자동조치 스크립트가 추가, 승인됨)\n'
        printf 'createUser %s SHA "%s" AES "%s"\n' "$KISA_U59_V3_USER" "$KISA_U59_V3_AUTHPASS" "$KISA_U59_V3_PRIVPASS"
        printf 'rouser %s\n' "$KISA_U59_V3_USER"
    } >> "$conf"

    if command -v systemctl >/dev/null 2>&1 && systemctl is-active snmpd >/dev/null 2>&1; then systemctl restart snmpd >/dev/null 2>&1 || { FIX_DETAIL="snmpd 재시작 실패."; return 2; }; fi

    FIX_DETAIL="${conf} 의 v1/v2c community 설정을 비활성화(주석 처리)하고 SNMPv3 사용자(${KISA_U59_V3_USER})를 생성함(백업: ${backup}). 모니터링 도구 측 설정도 SNMPv3 로 함께 변경해야 함."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-59 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
