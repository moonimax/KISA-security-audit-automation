#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-18"
readonly ITEM_TITLE="/etc/shadow 파일 소유자 및 권한 설정"
readonly ACTION_TAG="자동조치"
readonly IMPACT="파일 소유자/권한만 변경되며 서비스 재시작이 불필요함. passwd/login 등 관련 유틸리티는 setuid-root 로 동작하므로 일반적으로 영향이 없으나, 커스텀 스크립트가 비root 권한으로 shadow 를 직접 읽는 경우가 있다면 확인이 필요함"
readonly SEVERITY="상"
readonly TARGET_FILE="/etc/shadow"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    if [ ! -e "$TARGET_FILE" ]; then
        CHECK_DETAIL="${TARGET_FILE} 파일이 존재하지 않아 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    local owner perm reasons=()
    owner="$(stat -L -c '%U' "$TARGET_FILE" 2>/dev/null)"
    perm="$(stat -L -c '%a' "$TARGET_FILE" 2>/dev/null)"
    if [ -z "$owner" ] || [ -z "$perm" ]; then
        CHECK_DETAIL="${TARGET_FILE} 정보를 조회할 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    [ "$owner" != "root" ] && reasons+=("소유자가 root 가 아님(현재: ${owner})")
    local perm_last2="${perm: -2}"
    local group="${perm_last2:0:1}" other="${perm_last2:1:1}"
    [ $(( other )) -ne 0 ] && reasons+=("other 에 권한이 부여됨(현재: ${perm})")
    [ $(( group & 2 )) -ne 0 ] && reasons+=("group 쓰기 권한이 부여됨(현재: ${perm})")

    if [ "${#reasons[@]}" -eq 0 ]; then
        CHECK_DETAIL="${TARGET_FILE} 소유자=${owner}, 권한=${perm} 로 기준을 충족함."
        return "$KISA_EXIT_GOOD"
    fi
    CHECK_DETAIL="$(IFS='; '; echo "${reasons[*]}")"
    return "$KISA_EXIT_VULN"
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

    local target_owner="root:root" applied_perm=400
    if getent group shadow >/dev/null 2>&1; then
        target_owner="root:shadow"
        applied_perm=440
    fi

    local ok=1
    chown "$target_owner" "$TARGET_FILE" 2>/dev/null && chmod "$applied_perm" "$TARGET_FILE" 2>/dev/null && ok=0

    if [ "$ok" -ne 0 ]; then
        FIX_DETAIL="${TARGET_FILE} 소유자/권한 변경 명령이 실패함."
        return 2
    fi
    FIX_DETAIL="${TARGET_FILE} 소유자를 ${target_owner}, 권한을 ${applied_perm} 으로 설정함."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-18 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
