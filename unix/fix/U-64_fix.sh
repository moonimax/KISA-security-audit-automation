#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-64"
readonly ITEM_TITLE="주기적 보안 패치 및 벤더 권고사항 적용"
readonly ACTION_TAG="승인요청"
readonly IMPACT="패키지 업데이트는 커널/라이브러리 교체로 인한 서비스 재시작·재부팅이 필요할 수 있고 의존성 충돌 등 예측 불가한 영향을 줄 수 있어 반드시 관리자 승인 및 사전 검토가 필요함"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    if command -v rpm >/dev/null 2>&1 && rpm -q dnf-automatic >/dev/null 2>&1; then
        if ! systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1 \
            || ! systemctl is-active dnf-automatic.timer >/dev/null 2>&1; then
            CHECK_DETAIL="dnf-automatic은 설치되어 있으나 dnf-automatic.timer가 enable/active 상태가 아님."
            return "$KISA_EXIT_VULN"
        fi
    fi
    if command -v apt-get >/dev/null 2>&1; then
        local upgradable
        upgradable="$(apt list --upgradable 2>/dev/null | grep -vc '^Listing...')"
        if [ "${upgradable:-0}" -gt 0 ]; then
            CHECK_DETAIL="apt 기준 설치 가능한 업데이트가 ${upgradable}건 있음(로컬 패키지 인덱스 기준)."
            return "$KISA_EXIT_VULN"
        fi
        CHECK_DETAIL="apt 기준 설치 가능한 업데이트가 없음(로컬 패키지 인덱스 기준)."
        return "$KISA_EXIT_GOOD"
    fi
    if command -v dnf >/dev/null 2>&1; then
        local count
        count="$(dnf check-update --cacheonly 2>/dev/null | grep -cE '^[^[:space:]]+\.[a-zA-Z0-9_]+[[:space:]]')"
        if [ "${count:-0}" -gt 0 ]; then
            CHECK_DETAIL="dnf 기준 설치 가능한 업데이트가 ${count}건 있음(로컬 캐시 기준)."
            return "$KISA_EXIT_VULN"
        fi
        CHECK_DETAIL="dnf 기준 설치 가능한 업데이트가 없음(로컬 캐시 기준)."
        return "$KISA_EXIT_GOOD"
    fi
    if command -v yum >/dev/null 2>&1; then
        local count
        count="$(yum check-update --cacheonly 2>/dev/null | grep -cE '^[^[:space:]]+\.[a-zA-Z0-9_]+[[:space:]]')"
        if [ "${count:-0}" -gt 0 ]; then
            CHECK_DETAIL="yum 기준 설치 가능한 업데이트가 ${count}건 있음(로컬 캐시 기준)."
            return "$KISA_EXIT_VULN"
        fi
        CHECK_DETAIL="yum 기준 설치 가능한 업데이트가 없음(로컬 캐시 기준)."
        return "$KISA_EXIT_GOOD"
    fi
    CHECK_DETAIL="지원되는 패키지 매니저(apt/dnf/yum)를 찾을 수 없어 판정이 불가능함."
    return "$KISA_EXIT_FAIL"
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

    local pkg_list=""
    if command -v apt-get >/dev/null 2>&1; then
        pkg_list="$(apt list --upgradable 2>/dev/null | grep -v '^Listing...' | awk -F/ '{print $1}' | head -n 30 | tr '\n' ',' | sed 's/,$//')"
    elif command -v dnf >/dev/null 2>&1; then
        pkg_list="$(dnf check-update --cacheonly 2>/dev/null | grep -E '^[^[:space:]]+\.[a-zA-Z0-9_]+[[:space:]]' | awk '{print $1}' | head -n 30 | tr '\n' ',' | sed 's/,$//')"
    elif command -v yum >/dev/null 2>&1; then
        pkg_list="$(yum check-update --cacheonly 2>/dev/null | grep -E '^[^[:space:]]+\.[a-zA-Z0-9_]+[[:space:]]' | awk '{print $1}' | head -n 30 | tr '\n' ',' | sed 's/,$//')"
    fi

    if is_approved; then
        local timer_restored=false
        if command -v rpm >/dev/null 2>&1 && rpm -q dnf-automatic >/dev/null 2>&1 \
            && { ! systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1 \
                || ! systemctl is-active dnf-automatic.timer >/dev/null 2>&1; }; then
            if systemctl enable --now dnf-automatic.timer >/dev/null 2>&1; then
                timer_restored=true
            else
                FIX_DETAIL="dnf-automatic.timer enable --now 실패."
                return 2
            fi
        fi
        do_check
        local after=$?
        if [ "$after" -eq "$KISA_EXIT_GOOD" ]; then
            FIX_DETAIL="dnf-automatic.timer 복구=${timer_restored}. 현재 보류 업데이트가 없어 양호 상태를 확인함."
            return 0
        fi
        FIX_DETAIL="dnf-automatic.timer 복구=${timer_restored}. 패키지 업그레이드는 자동 실행하지 않으므로 변경관리 후 수동 패치 필요. 보류 중인 패키지(최대 30건): ${pkg_list:-확인 불가}."
    else
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청) 이전에도, 이 항목은 자동 패치 적용을 지원하지 않음(항상 수동 적용 대상). 보류 중인 패키지(최대 30건): ${pkg_list:-확인 불가}."
    fi
    return 1
}

do_fix
KISA_FIX_RC=$?
log_info "U-64 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
