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
FIX_DETAIL=""

_collect_start_scripts() {
    local dirs=(/etc/init.d /etc/rc0.d /etc/rc1.d /etc/rc2.d /etc/rc3.d /etc/rc4.d /etc/rc5.d /etc/rc6.d /etc/systemd/system)
    local files=()
    for d in "${dirs[@]}"; do
        [ -d "$d" ] || continue
        while IFS= read -r -d '' f; do
            files+=("$f")
        done < <(find "$d" -maxdepth 1 -type f -print0 2>/dev/null)
    done
    [ -e /etc/rc.local ] && [ -f /etc/rc.local ] && files+=(/etc/rc.local)
    printf '%s\n' "${files[@]}"
}

do_check() {
    local files
    mapfile -t files < <(_collect_start_scripts)

    if [ "${#files[@]}" -eq 0 ] || { [ "${#files[@]}" -eq 1 ] && [ -z "${files[0]}" ]; }; then
        CHECK_DETAIL="점검 대상 시작 스크립트가 없어 해당 사항 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    local offenders=() count=0
    for f in "${files[@]}"; do
        [ -z "$f" ] && continue
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
        CHECK_DETAIL="소유자가 root 가 아니거나 other 쓰기 권한이 있는 시작 스크립트 ${count}건 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="점검된 시작 스크립트 ${#files[@]}건 모두 기준을 충족함."
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

    local files
    mapfile -t files < <(_collect_start_scripts)

    local fixed=0 failed=0
    for f in "${files[@]}"; do
        [ -z "$f" ] && continue
        local owner perm other
        owner="$(stat -L -c '%U' "$f" 2>/dev/null)"
        perm="$(stat -L -c '%a' "$f" 2>/dev/null)"
        [ -z "$owner" ] || [ -z "$perm" ] && continue
        other="${perm: -1}"
        if [ "$owner" != "root" ] || [ $(( other & 2 )) -ne 0 ]; then
            if chown root:root "$f" 2>/dev/null && chmod o-w "$f" 2>/dev/null; then
                fixed=$((fixed + 1))
            else
                failed=$((failed + 1))
            fi
        fi
    done

    log_info "시작 스크립트 권한 조치: 성공 ${fixed}건, 실패 ${failed}건"

    if [ "$fixed" -eq 0 ] && [ "$failed" -eq 0 ]; then
        FIX_DETAIL="조치 대상 파일을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi
    if [ "$failed" -gt 0 ] && [ "$fixed" -eq 0 ]; then
        FIX_DETAIL="시작 스크립트 권한 조치에 모두 실패함(${failed}건)."
        return 2
    fi

    FIX_DETAIL="시작 스크립트 ${fixed}건의 소유자를 root:root 로, other 쓰기 권한을 제거함(실패 ${failed}건)."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-17 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
