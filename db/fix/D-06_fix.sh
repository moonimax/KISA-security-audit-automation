#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/mysql_lib.sh"

readonly ITEM_CODE="D-06"
readonly ITEM_TITLE="DB 사용자 계정을 개별적으로 부여하여 사용 (자동판정 불가, 수동 검토 필요)"
readonly ACTION_TAG="승인요청"
readonly IMPACT="일반적인 경우 영향 없음"
readonly SEVERITY="중"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    local rows
    rows="$(mysql_exec "SELECT CONCAT(user,'@',host) FROM mysql.user \
        WHERE user REGEXP '^(app|shared|common|service|admin|db|sys)[_0-9]*\$';")"
    CHECK_DETAIL="공용 계정으로 의심되는 이름: ${rows:-없음(단, 실제 공유 여부는 접속 로그/운영 정책 확인 필요)}"
    return "$KISA_EXIT_MANUAL"
}

do_fix() {
    do_check
    FIX_DETAIL="자동 조치 불가 - 계정을 개별/공용 중 어떻게 부여할지는 업무 특성에 따른 관리자 판단이 필요합니다. 접속 로그/운영 정책을 확인해 수동으로 검토하세요."
    return "$KISA_EXIT_MANUAL"
}

do_fix
KISA_FIX_RC=$?
log_info "D-06 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
