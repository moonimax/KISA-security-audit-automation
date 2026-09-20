#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-51"
readonly ITEM_TITLE="DNS 서비스의 취약한 동적 업데이트 설정 금지"
readonly ACTION_TAG="승인요청"
readonly IMPACT="어떤 클라이언트(DHCP 서버 등)에 동적 업데이트가 필요한지 관리자 판단이 필요하며, named.conf 변경 후 reload/reconfig 가 필요해 관리자 승인이 필요함"
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

    local offenders=()
    for c in "${confs[@]}"; do
        [ -z "$c" ] && continue
        if grep -Eq '^[[:space:]]*allow-update[[:space:]]*\{' "$c" 2>/dev/null; then
            grep -E '^[[:space:]]*allow-update[[:space:]]*\{' "$c" 2>/dev/null | grep -qi 'any' \
                && offenders+=("$c")
        fi
    done

    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="동적 업데이트가 전체 허용으로 설정된 곳 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="allow-update 가 없거나 전체 허용('any')으로 설정되어 있지 않음."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
