#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-20"
readonly ITEM_TITLE="/etc/(x)inetd.conf 파일 소유자 및 권한 설정"
readonly ACTION_TAG="자동조치"
readonly IMPACT="파일 소유자/권한만 변경되며 서비스 재시작이 불필요함. (x)inetd 데몬은 다음 재시작 시점부터 새 파일 권한으로 동작하며, 이미 기동된 슈퍼데몬의 현재 동작에는 영향이 없음"
readonly SEVERITY="중"

CHECK_DETAIL=""

do_check() {
    local targets=()
    [ -e /etc/inetd.conf ] && targets+=(/etc/inetd.conf)
    [ -e /etc/xinetd.conf ] && targets+=(/etc/xinetd.conf)
    if [ -d /etc/xinetd.d ]; then
        while IFS= read -r -d '' f; do
            targets+=("$f")
        done < <(find /etc/xinetd.d -maxdepth 1 -type f -print0 2>/dev/null)
    fi

    if [ "${#targets[@]}" -eq 0 ]; then
        CHECK_DETAIL="inetd.conf/xinetd.conf/xinetd.d 를 찾을 수 없어 (x)inetd 미사용으로 판단됨. 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    local offenders=()
    for f in "${targets[@]}"; do
        local owner perm
        owner="$(stat -L -c '%U' "$f" 2>/dev/null)"
        perm="$(stat -L -c '%a' "$f" 2>/dev/null)"
        [ -z "$owner" ] || [ -z "$perm" ] && continue
        local perm_last2="${perm: -2}"
        local group="${perm_last2:0:1}" other="${perm_last2:1:1}"
        if [ "$owner" != "root" ] || [ "$group" -ne 0 ] || [ "$other" -ne 0 ]; then
            offenders+=("${f}(owner=${owner},perm=${perm})")
        fi
    done

    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="소유자가 root 가 아니거나 group/other 권한이 있는 (x)inetd 설정 파일 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="점검된 (x)inetd 설정 파일 ${#targets[@]}건 모두 소유자 root, 권한 600 이하를 충족함."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
