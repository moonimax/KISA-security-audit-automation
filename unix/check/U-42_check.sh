#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-42"
readonly ITEM_TITLE="불필요한 RPC 서비스 비활성화"
readonly ACTION_TAG="승인요청"
readonly IMPACT="서비스 중지(stop/disable)를 수반하는 변경으로, RPC 기반 서비스(NFS/NIS 등)를 사용 중인 클라이언트가 있다면 즉시 영향을 받을 수 있어 관리자 승인이 필요함"
readonly SEVERITY="중"

CHECK_DETAIL=""

do_check() {
    local rpcbind_active="false"
    if command -v systemctl >/dev/null 2>&1; then
        for svc in rpcbind portmap; do
            systemctl is-active "$svc" >/dev/null 2>&1 && rpcbind_active="true"
        done
    fi

    if [ "$rpcbind_active" = "false" ]; then
        CHECK_DETAIL="rpcbind(portmap) 서비스가 비활성 상태이거나 설치되어 있지 않음."
        return "$KISA_EXIT_GOOD"
    fi

    CHECK_DETAIL="rpcbind 가 활성 상태임. RPC 의존 서비스의 업무상 필요 여부를 관리자 확인해야 함."
    return "$KISA_EXIT_VULN"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
