#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-38"
readonly ITEM_TITLE="DoS 공격에 취약한 서비스 비활성화"
readonly ACTION_TAG="승인요청"
readonly IMPACT="서비스 중지(stop/disable)를 수반하는 변경으로, 해당 서비스에 의존하는 예상치 못한 클라이언트(예: 네트워크 장비 진단 도구)가 있을 경우 즉시 영향을 받을 수 있어 관리자 승인이 필요함"
readonly SEVERITY="중"
readonly DOS_SERVICES=(echo echo-udp discard discard-udp daytime daytime-udp chargen chargen-udp)

CHECK_DETAIL=""

do_check() {
    local evidences=()

    for svc in "${DOS_SERVICES[@]}"; do
        local f="/etc/xinetd.d/${svc}"
        if [ -f "$f" ] && ! grep -qE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$f" 2>/dev/null; then
            evidences+=("${f} 활성화됨")
        fi
    done

    if [ -r /etc/inetd.conf ]; then
        for svc in echo discard daytime chargen; do
            grep -Eq "^[[:space:]]*${svc}[[:space:]]" /etc/inetd.conf 2>/dev/null && evidences+=("/etc/inetd.conf 에 ${svc} 활성 라인 존재")
        done
    fi

    if [ "${#evidences[@]}" -gt 0 ]; then
        CHECK_DETAIL="DoS 취약 서비스가 활성화되어 있음: $(IFS='; '; echo "${evidences[*]}")"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="echo/discard/daytime/chargen 서비스가 비활성화되어 있거나 설치되어 있지 않음."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
