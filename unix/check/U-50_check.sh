#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-50"
readonly ITEM_TITLE="DNS ZoneTransfer 설정"
readonly ACTION_TAG="승인요청"
readonly IMPACT="어떤 호스트(2차 네임서버)를 허용할지는 관리자 판단이 반드시 필요하며, named.conf 변경 후 reload/reconfig 가 필요해 승인이 필요함"
readonly SEVERITY="상"

CHECK_DETAIL=""

_find_named_confs() {
    local confs=()
    for f in /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options /etc/bind/named.conf.local; do
        [ -r "$f" ] && confs+=("$f")
    done
    printf '%s\n' "${confs[@]}"
}

do_check() {
    local confs
    mapfile -t confs < <(_find_named_confs)

    if ! command -v named >/dev/null 2>&1 && { [ "${#confs[@]}" -eq 0 ] || { [ "${#confs[@]}" -eq 1 ] && [ -z "${confs[0]}" ]; }; }; then
        CHECK_DETAIL="named(BIND) 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    if [ "${#confs[@]}" -eq 0 ] || { [ "${#confs[@]}" -eq 1 ] && [ -z "${confs[0]}" ]; }; then
        CHECK_DETAIL="named 는 설치되어 있으나 설정 파일을 찾을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    local offenders=() any_allow_transfer_found="false"
    for c in "${confs[@]}"; do
        [ -z "$c" ] && continue
        if grep -Eq '^[[:space:]]*allow-transfer[[:space:]]*\{' "$c" 2>/dev/null; then
            any_allow_transfer_found="true"
            if grep -EA1 '^[[:space:]]*allow-transfer[[:space:]]*\{' "$c" 2>/dev/null | grep -qi 'any'; then
                offenders+=("${c}(allow-transfer 에 any 포함)")
            fi
        fi
    done

    if [ "$any_allow_transfer_found" = "false" ]; then
        CHECK_DETAIL="점검된 설정 파일 어디에도 allow-transfer 제한이 없어 기본 정책(전체 허용)이 적용됨."
        return "$KISA_EXIT_VULN"
    fi

    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="Zone Transfer 가 전체 허용으로 설정된 곳 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="확인된 allow-transfer 설정이 특정 호스트로 제한되어 있음."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
