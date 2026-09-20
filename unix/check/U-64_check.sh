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

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
