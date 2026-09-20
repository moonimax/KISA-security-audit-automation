#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-11"
readonly ITEM_TITLE="사용자 shell 점검"
readonly ACTION_TAG="자동조치"
readonly IMPACT="대상 계정의 로그인 셸만 nologin으로 변경되며 서비스 재시작이 불필요함. usermod -s 로 즉시 되돌릴 수 있는 가역적 변경이나, 극히 일부 특수 목적 서비스 계정이 셸 실행을 필요로 하는 경우 영향이 있을 수 있음"
readonly SEVERITY="하"
readonly LOGIN_DEFS="/etc/login.defs"
readonly NONINTERACTIVE_RE='(nologin|false|sync|halt|shutdown|true)$'

CHECK_DETAIL=""

do_check() {
    if [ ! -r /etc/passwd ]; then
        CHECK_DETAIL="/etc/passwd 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    local sys_min sys_max
    sys_min="$(awk '/^[[:space:]]*SYS_UID_MIN[[:space:]]/{print $2; exit}' "$LOGIN_DEFS" 2>/dev/null)"
    sys_max="$(awk '/^[[:space:]]*SYS_UID_MAX[[:space:]]/{print $2; exit}' "$LOGIN_DEFS" 2>/dev/null)"
    sys_min="${sys_min:-1}"
    sys_max="${sys_max:-999}"

    local offenders
    offenders="$(awk -F: -v lo="$sys_min" -v hi="$sys_max" \
        '$3>=lo && $3<=hi && $3!=0 {print $1":"$7}' /etc/passwd \
        | grep -vE ":(.*/)?${NONINTERACTIVE_RE}" \
        | awk -F: '{print $1}' | tr '\n' ',' | sed 's/,$//')"

    if [ -n "$offenders" ]; then
        CHECK_DETAIL="대화형 로그인 셸이 부여된 시스템 계정(UID ${sys_min}~${sys_max}) 발견: ${offenders}"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="UID ${sys_min}~${sys_max} 범위의 시스템 계정은 모두 nologin/false 등 비대화형 셸을 사용 중임."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
