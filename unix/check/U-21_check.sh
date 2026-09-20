#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-21"
readonly ITEM_TITLE="/etc/(r)syslog.conf 파일 소유자 및 권한 설정"
readonly ACTION_TAG="자동조치"
readonly IMPACT="파일 소유자/권한만 변경되며 서비스 재시작이 불필요함. syslog/rsyslog 데몬은 다음 재시작 시점부터 새 권한으로 파일을 다루며, 이미 열려 있는 로그 파일 디스크립터에는 영향이 없음"
readonly SEVERITY="하"

CHECK_DETAIL=""

_collect_syslog_targets() {
    local targets=()
    [ -e /etc/syslog.conf ] && targets+=(/etc/syslog.conf)
    [ -e /etc/rsyslog.conf ] && targets+=(/etc/rsyslog.conf)
    if [ -d /etc/rsyslog.d ]; then
        while IFS= read -r -d '' f; do
            targets+=("$f")
        done < <(find /etc/rsyslog.d -maxdepth 1 -type f -name '*.conf' -print0 2>/dev/null)
    fi
    printf '%s\n' "${targets[@]}"
}

do_check() {
    local targets
    mapfile -t targets < <(_collect_syslog_targets)

    if [ "${#targets[@]}" -eq 0 ] || { [ "${#targets[@]}" -eq 1 ] && [ -z "${targets[0]}" ]; }; then
        CHECK_DETAIL="syslog.conf/rsyslog.conf/rsyslog.d 를 찾을 수 없어 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    local offenders=()
    for f in "${targets[@]}"; do
        [ -z "$f" ] && continue
        local owner perm other
        owner="$(stat -L -c '%U' "$f" 2>/dev/null)"
        perm="$(stat -L -c '%a' "$f" 2>/dev/null)"
        [ -z "$owner" ] || [ -z "$perm" ] && continue
        other="${perm: -1}"
        if [ "$owner" != "root" ] || [ $(( other & 2 )) -ne 0 ]; then
            offenders+=("${f}(owner=${owner},perm=${perm})")
        fi
    done

    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="소유자가 root 가 아니거나 other 쓰기 권한이 있는 (r)syslog 설정 파일 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="점검된 (r)syslog 설정 파일 ${#targets[@]}건 모두 기준을 충족함."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
