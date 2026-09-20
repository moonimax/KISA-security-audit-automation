#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-49"
readonly ITEM_TITLE="DNS 보안 버전 패치"
readonly ACTION_TAG="승인요청"
readonly IMPACT="BIND 보안 패키지 업데이트와 데몬 재시작이 필요해 관리자 승인이 필요함"
readonly SEVERITY="중"

CHECK_DETAIL=""

_find_named_conf() {
    for f in /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options; do
        [ -r "$f" ] && { printf '%s' "$f"; return 0; }
    done
    return 1
}

_bind_package_state() {
    if command -v rpm >/dev/null 2>&1 && rpm -q bind >/dev/null 2>&1; then
        local version rc; version="$(rpm -q bind 2>/dev/null)"
        if ! find /var/cache/dnf /var/cache/yum -type f -mtime -7 -print -quit 2>/dev/null | grep -q .; then
            printf 'stale:%s' "$version"; return 1
        fi
        if command -v dnf >/dev/null 2>&1; then dnf -q --cacheonly check-update --security 'bind*' >/dev/null 2>&1; rc=$?
        elif command -v yum >/dev/null 2>&1; then yum -q -C check-update --security 'bind*' >/dev/null 2>&1; rc=$?
        else printf 'fail:%s' "$version"; return 2; fi
        [ "$rc" -eq 100 ] && { printf 'update:%s' "$version"; return 1; }
        [ "$rc" -eq 0 ] && { printf 'current:%s' "$version"; return 0; }
        printf 'fail:%s' "$version"; return 2
    fi
    if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Status} ${Version}\n' bind9 2>/dev/null | grep -q '^install ok installed'; then
        local version; version="$(dpkg-query -W -f='${Version}' bind9 2>/dev/null)"
        if ! find /var/lib/apt/lists -type f -mtime -7 -print -quit 2>/dev/null | grep -q .; then
            printf 'stale:%s' "$version"; return 1
        fi
        if command -v apt >/dev/null 2>&1 && apt list --upgradable 2>/dev/null | grep -qE '^bind9(/|-)'; then printf 'update:%s' "$version"; return 1; fi
        printf 'current:%s' "$version"; return 0
    fi
    return 3
}
do_check() {
    local state rc; state="$(_bind_package_state)"; rc=$?
    [ "$rc" -eq 3 ] && { CHECK_DETAIL="BIND 패키지가 설치되어 있지 않아 해당 없음(양호)."; return "$KISA_EXIT_GOOD"; }
    [ "$rc" -eq 0 ] && { CHECK_DETAIL="패키지 캐시 기준 최신 BIND 보안 패치 상태: ${state#current:}."; return "$KISA_EXIT_GOOD"; }
    [ "$rc" -eq 1 ] && { CHECK_DETAIL="BIND 보안 업데이트 또는 7일 이내 패키지 메타데이터 갱신이 필요함: ${state}."; return "$KISA_EXIT_VULN"; }
    CHECK_DETAIL="BIND 버전은 확인했으나 패키지 캐시로 보안 패치 상태를 판정할 수 없음($state)."; return "$KISA_EXIT_FAIL"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
