#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-26"
readonly ITEM_TITLE="/dev에 존재하지 않는 device 파일 점검"
readonly ACTION_TAG="승인요청"
readonly IMPACT="발견된 디바이스 파일이 정상 설치 과정의 잔재인지 은닉 채널인지 판단이 필요하며, 삭제(rm)는 되돌릴 수 없는 파괴적 변경이라 관리자 확인 없이 자동 실행하지 않음"
readonly SEVERITY="상"
readonly SCAN_TIMEOUT="${KISA_U26_SCAN_TIMEOUT:-30}"
readonly QUARANTINE_DIR="/var/quarantine/kisa_u26"

CHECK_DETAIL=""
FIX_DETAIL=""

_scan_stray_devices() {
    if command -v timeout >/dev/null 2>&1; then
        timeout "$SCAN_TIMEOUT" find /dev -xdev -type f -print 2>/dev/null
    else
        find /dev -xdev -type f -print 2>/dev/null
    fi
}

do_check() {
    command -v find >/dev/null 2>&1 || { CHECK_DETAIL="find 명령을 찾을 수 없어 판정이 불가능함."; return "$KISA_EXIT_FAIL"; }
    [ -d /dev ] || { CHECK_DETAIL="/dev 디렉토리가 없어 판정이 불가능함."; return "$KISA_EXIT_FAIL"; }
    local result rc
    if command -v timeout >/dev/null 2>&1; then
        result="$(timeout "$SCAN_TIMEOUT" find /dev -xdev -type f -print 2>/dev/null)"; rc=$?
    else
        result="$(find /dev -xdev -type f -print 2>/dev/null)"; rc=$?
    fi
    [ "$rc" -eq 124 ] && { CHECK_DETAIL="/dev 일반 파일 스캔이 ${SCAN_TIMEOUT}초 내에 끝나지 않음."; return "$KISA_EXIT_FAIL"; }
    [ "$rc" -eq 0 ] || { CHECK_DETAIL="/dev 일반 파일 스캔 명령이 실패함(rc=$rc)."; return "$KISA_EXIT_FAIL"; }
    if [ -n "$result" ]; then
        CHECK_DETAIL="/dev 내부 일반 파일 $(printf '%s\n' "$result" | grep -c .)건 발견: $(printf '%s\n' "$result" | tr '\n' ',' | sed 's/,$//')"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="/dev 내부에 일반 파일이 존재하지 않음."
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): /dev 내부 일반 파일이 정상 잔재물인지 침해 흔적인지 확인이 필요해 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하면 즉시 삭제하지 않고 격리 디렉토리(${QUARANTINE_DIR})로 이동함."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local files
    files="$(_scan_stray_devices)"
    if [ -z "$files" ]; then
        FIX_DETAIL="조치 대상 파일을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi

    local ts qdir
    ts="$(date +%Y%m%d%H%M%S)"
    qdir="${QUARANTINE_DIR}/${ts}"
    if ! mkdir -p "$qdir" 2>/dev/null; then
        FIX_DETAIL="격리 디렉토리(${qdir}) 생성에 실패하여 조치를 중단함."
        return 2
    fi
    chmod 700 "$qdir" 2>/dev/null

    local moved=0 failed=0 moved_list=""
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        local dest="${qdir}/$(printf '%s' "$f" | tr '/' '_')"
        if mv "$f" "$dest" 2>/dev/null; then
            moved=$((moved + 1))
            moved_list="${moved_list}${moved_list:+,}${f}->${dest}"
        else
            failed=$((failed + 1))
        fi
    done <<< "$files"

    log_info "격리 처리: 성공 ${moved}건, 실패 ${failed}건, 격리 위치 ${qdir}"

    if [ "$moved" -eq 0 ] && [ "$failed" -gt 0 ]; then
        FIX_DETAIL="디바이스 파일 격리에 모두 실패함(${failed}건)."
        return 2
    fi

    FIX_DETAIL="/dev 내부 일반 파일 ${moved}건을 삭제 대신 격리 디렉토리(${qdir})로 이동함(실패 ${failed}건). 최종 영구 삭제는 관리자가 내용을 검토한 뒤 결정해야 함: ${moved_list}"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-26 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
