#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-37"
readonly ITEM_TITLE="crontab 설정파일 권한 설정 미흡"
readonly ACTION_TAG="자동조치"
readonly IMPACT="파일 소유자/권한만 변경되며 cron 데몬 재시작이 불필요함(cron 은 매 분 파일을 다시 읽으므로 이미 등록된 작업 실행에는 영향이 없음)"
readonly SEVERITY="중"

CHECK_DETAIL=""

_collect_cron_targets() {
    local targets=()
    [ -e /etc/crontab ] && targets+=(/etc/crontab)
    [ -e /etc/cron.allow ] && targets+=(/etc/cron.allow)
    [ -e /etc/cron.deny ] && targets+=(/etc/cron.deny)
    if [ -d /etc/cron.d ]; then
        while IFS= read -r -d '' f; do targets+=("$f"); done \
            < <(find /etc/cron.d -maxdepth 1 -type f -print0 2>/dev/null)
    fi
    for spool in /var/spool/cron/crontabs /var/spool/cron; do
        [ -d "$spool" ] || continue
        while IFS= read -r -d '' f; do targets+=("$f"); done \
            < <(find "$spool" -maxdepth 1 -type f -print0 2>/dev/null)
    done
    printf '%s\n' "${targets[@]}"
}

do_check() {
    local targets
    mapfile -t targets < <(_collect_cron_targets)

    if [ "${#targets[@]}" -eq 0 ] || { [ "${#targets[@]}" -eq 1 ] && [ -z "${targets[0]}" ]; }; then
        CHECK_DETAIL="점검 대상 crontab 관련 파일이 없어 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    local offenders=()
    for f in "${targets[@]}"; do
        [ -z "$f" ] && continue
        local owner perm
        owner="$(stat -L -c '%U' "$f" 2>/dev/null)"
        perm="$(stat -L -c '%a' "$f" 2>/dev/null)"
        [ -z "$owner" ] || [ -z "$perm" ] && continue
        local perm_last2="${perm: -2}"
        local group="${perm_last2:0:1}" other="${perm_last2:1:1}"
        if [ $(( group & 2 )) -ne 0 ] || [ $(( other & 2 )) -ne 0 ]; then
            offenders+=("${f}(owner=${owner},perm=${perm})")
        fi
    done

    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="group 또는 other 쓰기 권한이 있는 crontab 관련 파일 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="점검된 crontab 관련 파일 ${#targets[@]}건 모두 group/other 쓰기 권한이 없음."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
