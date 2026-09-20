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
FIX_DETAIL=""

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
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local targets
    mapfile -t targets < <(_collect_cron_targets)

    local fixed=0 failed=0
    for f in "${targets[@]}"; do
        [ -z "$f" ] && continue
        local owner perm
        owner="$(stat -L -c '%U' "$f" 2>/dev/null)"
        perm="$(stat -L -c '%a' "$f" 2>/dev/null)"
        [ -z "$owner" ] || [ -z "$perm" ] && continue
        local perm_last2="${perm: -2}"
        local group="${perm_last2:0:1}" other="${perm_last2:1:1}"
        if [ $(( group & 2 )) -ne 0 ] || [ $(( other & 2 )) -ne 0 ]; then
            if chmod go-w "$f" 2>/dev/null; then
                fixed=$((fixed + 1))
            else
                failed=$((failed + 1))
            fi
        fi
    done

    log_info "crontab 파일 권한 조치: 성공 ${fixed}건, 실패 ${failed}건"

    if [ "$fixed" -eq 0 ] && [ "$failed" -eq 0 ]; then
        FIX_DETAIL="조치 대상 파일을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi
    if [ "$failed" -gt 0 ] && [ "$fixed" -eq 0 ]; then
        FIX_DETAIL="crontab 파일 권한 조치에 모두 실패함(${failed}건)."
        return 2
    fi

    FIX_DETAIL="crontab 관련 파일 ${fixed}건에서 group/other 쓰기 권한을 제거함(실패 ${failed}건)."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-37 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
