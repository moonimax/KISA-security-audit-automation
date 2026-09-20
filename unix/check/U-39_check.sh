#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-39"
readonly ITEM_TITLE="불필요한 NFS 서비스 비활성화"
readonly ACTION_TAG="승인요청"
readonly IMPACT="서비스 중지(stop/disable)를 수반하는 변경으로, 실제로 NFS 공유를 사용 중인 클라이언트가 있다면 즉시 마운트 장애가 발생할 수 있어 관리자 승인이 필요함"
readonly SEVERITY="중"

CHECK_DETAIL=""

_nfs_service_active() {
    command -v systemctl >/dev/null 2>&1 || return 1
    for svc in nfs-server nfs-kernel-server nfsd; do
        systemctl is-active "$svc" >/dev/null 2>&1 && { printf '%s' "$svc"; return 0; }
    done
    return 1
}

do_check() {
    local active_svc
    active_svc="$(_nfs_service_active)"

    if [ -z "$active_svc" ]; then
        CHECK_DETAIL="NFS 서버 서비스가 비활성 상태이거나 설치되어 있지 않음."
        return "$KISA_EXIT_GOOD"
    fi

    CHECK_DETAIL="NFS 서비스(${active_svc})가 활성 상태임. 업무상 필요 여부는 관리자 확인이 필요하며 접근 통제는 U-40에서 별도 점검함."
    return "$KISA_EXIT_VULN"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
