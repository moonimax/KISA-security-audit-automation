#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-15"
readonly ITEM_TITLE="파일 및 디렉터리 소유자 설정"
readonly ACTION_TAG="승인요청"
readonly IMPACT="탐지된 파일의 실제 용도와 소유권 재지정(또는 삭제) 필요 여부는 관리자의 확인이 필요함. 소유자가 없는 파일은 삭제된 계정의 잔존물일 수도, 침해사고의 흔적일 수도 있어 자동으로 판단할 수 없는 항목임"
readonly SEVERITY="중"
readonly SCAN_TIMEOUT="${KISA_U15_SCAN_TIMEOUT:-30}"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    if ! command -v find >/dev/null 2>&1; then
        CHECK_DETAIL="find 명령을 찾을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    local result rc
    if command -v timeout >/dev/null 2>&1; then
        result="$(timeout "$SCAN_TIMEOUT" find / -xdev \( -nouser -o -nogroup \) -print 2>/dev/null | head -n 20)"
        rc=$?
    else
        result="$(find / -xdev \( -nouser -o -nogroup \) -print 2>/dev/null | head -n 20)"
        rc=0
    fi
    if [ "$rc" -eq 124 ]; then
        CHECK_DETAIL="파일시스템 전체 스캔이 ${SCAN_TIMEOUT}초 내에 끝나지 않아 판정을 완료하지 못함."
        return "$KISA_EXIT_FAIL"
    fi
    if [ -n "$result" ]; then
        local count sample
        count="$(printf '%s\n' "$result" | grep -c .)"
        sample="$(printf '%s\n' "$result" | tr '\n' ',' | sed 's/,$//')"
        CHECK_DETAIL="소유자/그룹 정보가 유효하지 않은 파일 ${count}건(최대 20건 표시) 발견: ${sample}"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="루트 파일시스템 내에서 소유자/그룹이 존재하지 않는 파일을 발견하지 못함."
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 소유자 없는 파일이 정상적인 잔존물인지 침해 흔적인지 확인이 필요해 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하면 root:root 로 소유권만 재지정하며(삭제 없음), 파일 내용 검토는 관리자가 수동으로 수행해야 함."
        return 1
    fi

    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi
    if ! command -v find >/dev/null 2>&1; then
        FIX_DETAIL="find 명령을 찾을 수 없어 조치를 수행할 수 없음."
        return 2
    fi

    local files
    if command -v timeout >/dev/null 2>&1; then
        files="$(timeout "$SCAN_TIMEOUT" find / -xdev \( -nouser -o -nogroup \) -print 2>/dev/null | head -n 200)"
    else
        files="$(find / -xdev \( -nouser -o -nogroup \) -print 2>/dev/null | head -n 200)"
    fi

    if [ -z "$files" ]; then
        FIX_DETAIL="조치 대상 파일을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi

    local ok_count=0 fail_count=0
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        if chown root:root "$f" 2>/dev/null; then
            ok_count=$((ok_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi
    done <<< "$files"

    log_info "소유자 없는 파일 chown 처리: 성공 ${ok_count}건, 실패 ${fail_count}건"

    if [ "$fail_count" -gt 0 ] && [ "$ok_count" -eq 0 ]; then
        FIX_DETAIL="소유권 재지정에 모두 실패함(${fail_count}건)."
        return 2
    fi

    FIX_DETAIL="소유자/그룹이 없던 파일 ${ok_count}건(최대 200건 처리)을 root:root 로 재지정함(삭제 없음, 실패 ${fail_count}건). 재지정된 파일의 실제 위협 여부는 관리자가 별도로 확인 필요."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-15 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
