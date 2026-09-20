#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-17"
readonly ITEM_TITLE="시스템 시작 스크립트 권한 설정"
readonly ACTION_TAG="자동조치"
readonly IMPACT="대상 파일들의 소유자/권한만 변경되며 서비스 재시작이 불필요함. 다음 부팅 또는 서비스 재시작 시점부터 정상적으로 재적용되므로 즉시 서비스에 영향을 주지 않음"
readonly SEVERITY="중"

CHECK_DETAIL=""

do_check() {
    local dirs=(/etc/init.d /etc/rc0.d /etc/rc1.d /etc/rc2.d /etc/rc3.d /etc/rc4.d /etc/rc5.d /etc/rc6.d /etc/systemd/system)
    local files=()

    for d in "${dirs[@]}"; do
        [ -d "$d" ] || continue
        while IFS= read -r -d '' f; do
            files+=("$f")
        done < <(find "$d" -maxdepth 1 -type f -print0 2>/dev/null)
    done
    [ -e /etc/rc.local ] && [ -f /etc/rc.local ] && files+=(/etc/rc.local)

    if [ "${#files[@]}" -eq 0 ]; then
        CHECK_DETAIL="점검 대상 시작 스크립트 경로가 존재하지 않거나 파일이 없어 해당 사항 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    local offenders=() count=0
    for f in "${files[@]}"; do
        local owner perm other
        owner="$(stat -L -c '%U' "$f" 2>/dev/null)"
        perm="$(stat -L -c '%a' "$f" 2>/dev/null)"
        [ -z "$owner" ] || [ -z "$perm" ] && continue
        other="${perm: -1}"
        if [ "$owner" != "root" ] || [ $(( other & 2 )) -ne 0 ]; then
            count=$((count + 1))
            [ "${#offenders[@]}" -lt 10 ] && offenders+=("${f}(owner=${owner},perm=${perm})")
        fi
    done

    if [ "$count" -gt 0 ]; then
        CHECK_DETAIL="소유자가 root 가 아니거나 other 쓰기 권한이 있는 시작 스크립트 ${count}건 발견(최대 10건 표시): $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="점검된 시작 스크립트 ${#files[@]}건 모두 소유자 root, other 쓰기 권한 없음을 확인함."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
