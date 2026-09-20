#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-25"
readonly ITEM_TITLE="world writable 파일 점검"
readonly ACTION_TAG="승인요청"
readonly IMPACT="chmod 로 other 쓰기 권한만 제거하는 가역적 변경이지만, 메일 스풀·IPC 소켓·공유 로그 등 의도적으로 world-writable 로 구성된 파일이 존재할 수 있어 개별 파일에 대한 관리자 검토 없이 일괄 조치할 경우 정상 서비스가 깨질 위험이 있음"
readonly SEVERITY="상"
readonly SCAN_TIMEOUT="${KISA_U25_SCAN_TIMEOUT:-30}"
readonly MAX_FIX_FILES=200

CHECK_DETAIL=""
FIX_DETAIL=""

_scan_ww_files() {
    local limit="${1:-30}"
    if command -v timeout >/dev/null 2>&1; then
        timeout "$SCAN_TIMEOUT" find / -xdev -type f -perm -0002 -print 2>/dev/null | head -n "$limit"
    else
        find / -xdev -type f -perm -0002 -print 2>/dev/null | head -n "$limit"
    fi
}

do_check() {
    if ! command -v find >/dev/null 2>&1; then
        CHECK_DETAIL="find 명령을 찾을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    local result rc
    result="$(_scan_ww_files 30)"
    rc=$?
    if [ "$rc" -eq 124 ]; then
        CHECK_DETAIL="world writable 파일 전체 스캔이 ${SCAN_TIMEOUT}초 내에 끝나지 않아 판정을 완료하지 못함."
        return "$KISA_EXIT_FAIL"
    fi
    if [ -n "$result" ]; then
        local count sample
        count="$(printf '%s\n' "$result" | grep -c .)"
        sample="$(printf '%s\n' "$result" | tr '\n' ',' | sed 's/,$//')"
        CHECK_DETAIL="world writable 일반 파일 ${count}건(최대 30건 표시) 발견: ${sample}"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="루트 파일시스템 내에서 world writable 파일을 발견하지 못함."
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

    if [ "$ACTION_TAG" = "승인요청" ] && ! is_approved; then
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): world-writable 파일이 의도된 구성인지 확인이 필요해 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하면 chmod o-w 로 other 쓰기 권한만 제거함(파일 삭제 없음)."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local files
    files="$(_scan_ww_files "$MAX_FIX_FILES")"

    if [ -z "$files" ]; then
        FIX_DETAIL="조치 대상 파일을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi

    local fixed=0 failed=0
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        if chmod o-w "$f" 2>/dev/null; then
            fixed=$((fixed + 1))
        else
            failed=$((failed + 1))
        fi
    done <<< "$files"

    log_info "world writable 파일 조치: 성공 ${fixed}건, 실패 ${failed}건"

    if [ "$fixed" -eq 0 ] && [ "$failed" -gt 0 ]; then
        FIX_DETAIL="world writable 파일 조치에 모두 실패함(${failed}건)."
        return 2
    fi

    FIX_DETAIL="world writable 파일 ${fixed}건(최대 ${MAX_FIX_FILES}건 처리)에서 other 쓰기 권한을 제거함(실패 ${failed}건)."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-25 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
