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
FIX_DETAIL=""

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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 서비스 중지가 필요한 항목이라 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하세요."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local applied=()
    for svc in rpcbind portmap; do
        if command -v systemctl >/dev/null 2>&1 && systemctl is-active "$svc" >/dev/null 2>&1; then
            if systemctl disable --now "$svc" >/dev/null 2>&1; then
                applied+=("systemd 서비스 ${svc} disable --now")
            else
                FIX_DETAIL="RPC 서비스 ${svc} 비활성화 실패."
                return 2
            fi
        fi
    done

    if [ "${#applied[@]}" -eq 0 ]; then
        FIX_DETAIL="조치 대상을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi
    FIX_DETAIL="$(IFS='; '; echo "${applied[*]}")"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-42 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
