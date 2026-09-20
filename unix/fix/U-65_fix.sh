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
FIX_DETAIL=""

do_check() {
    local evidence=""
    if command -v chronyc >/dev/null 2>&1; then chronyc tracking 2>/dev/null | grep -Eq '^Leap status[[:space:]]*:[[:space:]]*Normal' && chronyc sources 2>/dev/null | grep -Eq '^[#^=~]?\\*' && evidence="chrony 동기화 피어"; fi
    if [ -z "$evidence" ] && command -v ntpq >/dev/null 2>&1; then ntpq -pn 2>/dev/null | grep -Eq '^\\*' && evidence="ntpd 동기화 피어"; fi
    if [ -z "$evidence" ] && command -v timedatectl >/dev/null 2>&1; then timedatectl show 2>/dev/null | grep -q '^NTPSynchronized=yes' && evidence="timedatectl NTPSynchronized=yes"; fi
    if [ -n "$evidence" ]; then CHECK_DETAIL="실제 시각 동기화 성공 확인: $evidence"; return "$KISA_EXIT_GOOD"; fi
    CHECK_DETAIL="서비스 실행 여부와 별개로 실제 NTP 피어 선택/동기화 성공을 확인하지 못함."; return "$KISA_EXIT_VULN"
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 활성화 시 시간이 즉시 크게 보정될 수 있어 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하세요."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi
    if ! command -v systemctl >/dev/null 2>&1; then
        FIX_DETAIL="systemctl 명령을 찾을 수 없어 조치를 수행할 수 없음."
        return 2
    fi

    local candidates=(systemd-timesyncd chronyd chrony ntpd ntp)
    local activated=""
    for svc in "${candidates[@]}"; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service"; then
            if systemctl enable --now "$svc" >/dev/null 2>&1; then
                activated="$svc"
                break
            fi
        fi
    done

    if [ -z "$activated" ]; then
        FIX_DETAIL="시각 동기화 서비스 패키지(systemd-timesyncd/chrony/ntp)를 찾지 못해 활성화하지 못함. 패키지 설치가 필요할 수 있음."
        return 2
    fi

    FIX_DETAIL="시각 동기화 서비스(${activated})를 활성화 및 시작함. 실제 피어 동기화를 확인함."
    do_check
    [ $? -eq "$KISA_EXIT_GOOD" ] || { FIX_DETAIL="${FIX_DETAIL} 아직 실제 동기화가 확인되지 않음."; return 1; }
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-65 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
