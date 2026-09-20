#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-33"
readonly ITEM_TITLE="숨겨진 파일 및 디렉토리 검색 및 제거"
readonly ACTION_TAG="승인요청"
readonly IMPACT="탐지된 파일이 실제 악성/은닉 목적인지 정상 애플리케이션의 캐시 파일 등인지는 관리자의 확인이 필요하며, 삭제(rm)는 되돌릴 수 없는 파괴적 변경이라 자동으로 실행하지 않음"
readonly SEVERITY="상"
readonly SCAN_TIMEOUT="${KISA_U33_SCAN_TIMEOUT:-20}"
readonly QUARANTINE_DIR="/var/quarantine/kisa_u33"

CHECK_DETAIL=""
FIX_DETAIL=""

_scan_dirs() {
    local dirs=(/tmp /var/tmp /dev/shm)
    if [ -r /etc/passwd ]; then
        while IFS=: read -r _ _ _ _ _ home _; do
            [ -n "$home" ] && [ "$home" != "/" ] && [ -d "$home" ] && dirs+=("$home")
        done < /etc/passwd
    fi
    printf '%s\n' "${dirs[@]}" | sort -u
}

_scan_hidden_files() {
    local limit="${1:-20}"
    local dirs f_args=()
    mapfile -t dirs < <(_scan_dirs)
    for d in "${dirs[@]}"; do
        [ -d "$d" ] && f_args+=("$d")
    done
    [ "${#f_args[@]}" -eq 0 ] && return 0

    if command -v timeout >/dev/null 2>&1; then
        timeout "$SCAN_TIMEOUT" find "${f_args[@]}" -xdev -maxdepth 3 \
            \( -regex '.*/\.\.+' -o -regex '.*/\. +' -o -name ' ' \) \
            -not -name '.' -not -name '..' -print 2>/dev/null | head -n "$limit"
    else
        find "${f_args[@]}" -xdev -maxdepth 3 \
            \( -regex '.*/\.\.+' -o -regex '.*/\. +' -o -name ' ' \) \
            -not -name '.' -not -name '..' -print 2>/dev/null | head -n "$limit"
    fi
}

do_check() {
    if ! command -v find >/dev/null 2>&1; then
        CHECK_DETAIL="find 명령을 찾을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    local result rc
    result="$(_scan_hidden_files 20)"
    rc=$?
    if [ "$rc" -eq 124 ]; then
        CHECK_DETAIL="은닉 파일 스캔이 ${SCAN_TIMEOUT}초 내에 끝나지 않아 판정을 완료하지 못함."
        return "$KISA_EXIT_FAIL"
    fi
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 141 ]; then
        CHECK_DETAIL="은닉 파일 스캔 명령이 실패함(rc=${rc})."
        return "$KISA_EXIT_FAIL"
    fi
    if [ -n "$result" ]; then
        local count sample
        count="$(printf '%s\n' "$result" | grep -c .)"
        sample="$(printf '%s\n' "$result" | tr '\n' ',' | sed 's/,$//')"
        CHECK_DETAIL="이름을 위장한 은닉 파일/디렉토리 ${count}건(최대 20건 표시) 발견: ${sample}"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="점검 대상 경로에서 이름을 위장한 은닉 파일을 발견하지 못함."
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 은닉 파일이 악성인지 정상 파일인지 확인이 필요해 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하면 삭제 대신 격리 디렉토리(${QUARANTINE_DIR})로 이동함."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local files scan_rc
    files="$(_scan_hidden_files 200)"
    scan_rc=$?
    if [ "$scan_rc" -ne 0 ] && [ "$scan_rc" -ne 141 ]; then
        FIX_DETAIL="조치 대상 재스캔이 실패하거나 시간 초과됨(rc=${scan_rc})."
        return 2
    fi
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

    log_info "은닉 파일 격리: 성공 ${moved}건, 실패 ${failed}건, 위치 ${qdir}"

    if [ "$moved" -eq 0 ] && [ "$failed" -gt 0 ]; then
        FIX_DETAIL="은닉 파일 격리에 모두 실패함(${failed}건)."
        return 2
    fi

    FIX_DETAIL="은닉 파일 ${moved}건을 삭제 대신 격리 디렉토리(${qdir})로 이동함(실패 ${failed}건). 최종 영구 삭제는 관리자가 내용을 검토한 뒤 결정해야 함."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-33 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
