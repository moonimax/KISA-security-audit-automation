#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-43"
readonly ITEM_TITLE="NIS, NIS+ 점검"
readonly ACTION_TAG="승인요청"
readonly IMPACT="서비스 중지(stop/disable)를 수반하는 변경으로, 실제로 NIS 로 계정/그룹을 통합 관리 중인 환경이라면 인증 체계 전체에 영향을 줄 수 있어 관리자 승인이 필요함"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    local evidences=()
    if command -v systemctl >/dev/null 2>&1; then
        for svc in ypbind ypserv yppasswdd ypxfrd; do
            systemctl is-active "$svc" >/dev/null 2>&1 && evidences+=("systemd 서비스 ${svc} 활성")
        done
    fi
    if command -v pgrep >/dev/null 2>&1 && pgrep -x 'ypbind|ypserv' >/dev/null 2>&1; then
        evidences+=("ypbind/ypserv 프로세스 실행 중")
    fi
    if [ "${#evidences[@]}" -gt 0 ]; then
        CHECK_DETAIL="NIS 관련 서비스가 활성화되어 있음: $(IFS='; '; echo "${evidences[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="NIS(ypbind/ypserv) 서비스가 비활성화되어 있거나 설치되어 있지 않음."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
