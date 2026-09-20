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
FIX_DETAIL=""

_collect_inetd_targets() {
    local targets=()
    [ -e /etc/inetd.conf ] && targets+=(/etc/inetd.conf)
    [ -e /etc/xinetd.conf ] && targets+=(/etc/xinetd.conf)
    if [ -d /etc/xinetd.d ]; then
        while IFS= read -r -d '' f; do
            targets+=("$f")
        done < <(find /etc/xinetd.d -maxdepth 1 -type f -print0 2>/dev/null)
    fi
    printf '%s\n' "${targets[@]}"
}

do_check() {
    local targets
    mapfile -t targets < <(_collect_inetd_targets)

    if [ "${#targets[@]}" -eq 0 ] || { [ "${#targets[@]}" -eq 1 ] && [ -z "${targets[0]}" ]; }; then
        CHECK_DETAIL="inetd.conf/xinetd.conf/xinetd.d 를 찾을 수 없어 (x)inetd 미사용으로 판단됨. 해당 없음(양호)."
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
        if [ "$owner" != "root" ] || [ "$group" -ne 0 ] || [ "$other" -ne 0 ]; then
            offenders+=("${f}(owner=${owner},perm=${perm})")
        fi
    done

    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="소유자가 root 가 아니거나 group/other 권한이 있는 (x)inetd 설정 파일 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="점검된 (x)inetd 설정 파일 ${#targets[@]}건 모두 기준을 충족함."
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
    mapfile -t targets < <(_collect_inetd_targets)

    local fixed=0 failed=0
    for f in "${targets[@]}"; do
        [ -z "$f" ] && continue
        local owner perm
        owner="$(stat -L -c '%U' "$f" 2>/dev/null)"
        perm="$(stat -L -c '%a' "$f" 2>/dev/null)"
        [ -z "$owner" ] || [ -z "$perm" ] && continue
        local perm_last2="${perm: -2}"
        local group="${perm_last2:0:1}" other="${perm_last2:1:1}"
        if [ "$owner" != "root" ] || [ "$group" -ne 0 ] || [ "$other" -ne 0 ]; then
            if chown root:root "$f" 2>/dev/null && chmod 600 "$f" 2>/dev/null; then
                fixed=$((fixed + 1))
            else
                failed=$((failed + 1))
            fi
        fi
    done

    log_info "(x)inetd 설정 파일 권한 조치: 성공 ${fixed}건, 실패 ${failed}건"

    if [ "$fixed" -eq 0 ] && [ "$failed" -eq 0 ]; then
        FIX_DETAIL="조치 대상 파일을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi
    if [ "$failed" -gt 0 ] && [ "$fixed" -eq 0 ]; then
        FIX_DETAIL="(x)inetd 설정 파일 권한 조치에 모두 실패함(${failed}건)."
        return 2
    fi

    FIX_DETAIL="(x)inetd 설정 파일 ${fixed}건의 소유자를 root:root, 권한을 600 으로 설정함(실패 ${failed}건)."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-20 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
