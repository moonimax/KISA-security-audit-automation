#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-65"
readonly ITEM_TITLE="NTP 및 시각 동기화 설정"
readonly ACTION_TAG="승인요청"
readonly IMPACT="시각 동기화 서비스를 활성화하면 시스템 시간이 즉시 크게 보정될 수 있어(시간 점프) 로그 타임스탬프 연속성, TLS 인증서 유효기간 검증, cron/배치 스케줄 등에 순간적인 영향을 줄 수 있어 관리자 승인이 필요함"
readonly SEVERITY="중"

CHECK_DETAIL=""

do_check() {
    local evidence=""
    if command -v chronyc >/dev/null 2>&1; then chronyc tracking 2>/dev/null | grep -Eq '^Leap status[[:space:]]*:[[:space:]]*Normal' && chronyc sources 2>/dev/null | grep -Eq '^[#^=~]?\\*' && evidence="chrony 동기화 피어"; fi
    if [ -z "$evidence" ] && command -v ntpq >/dev/null 2>&1; then ntpq -pn 2>/dev/null | grep -Eq '^\\*' && evidence="ntpd 동기화 피어"; fi
    if [ -z "$evidence" ] && command -v timedatectl >/dev/null 2>&1; then timedatectl show 2>/dev/null | grep -q '^NTPSynchronized=yes' && evidence="timedatectl NTPSynchronized=yes"; fi
    if [ -n "$evidence" ]; then CHECK_DETAIL="실제 시각 동기화 성공 확인: $evidence"; return "$KISA_EXIT_GOOD"; fi
    CHECK_DETAIL="서비스 실행 여부와 별개로 실제 NTP 피어 선택/동기화 성공을 확인하지 못함."; return "$KISA_EXIT_VULN"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
