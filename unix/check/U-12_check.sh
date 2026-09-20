#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-12"
readonly ITEM_TITLE="세션 종료 시간 설정"
readonly ACTION_TAG="자동조치"
readonly IMPACT="신규 로그인 셸 프로파일에만 적용되는 설정 파일 추가로 서비스 재시작이 불필요함. 이미 접속 중인 세션에는 영향이 없고, 신규 세션부터 유휴 시간 초과 시 자동 로그아웃됨"
readonly SEVERITY="중"
readonly TMOUT_LIMIT=600

CHECK_DETAIL=""

do_check() {
    local candidates=(/etc/profile /etc/bashrc /etc/csh.login)
    if [ -d /etc/profile.d ]; then
        while IFS= read -r -d '' f; do
            candidates+=("$f")
        done < <(find /etc/profile.d -maxdepth 1 -type f -name '*.sh' -print0 2>/dev/null)
    fi

    local min_val=""
    for f in "${candidates[@]}"; do
        [ -r "$f" ] || continue
        local val
        val="$(grep -E '^[[:space:]]*(export[[:space:]]+)?TMOUT[[:space:]]*=' "$f" 2>/dev/null \
            | grep -v '^[[:space:]]*#' | tail -n1 | sed -E 's/.*TMOUT[[:space:]]*=[[:space:]]*([0-9]+).*/\1/')"
        if [[ "$val" =~ ^[0-9]+$ ]]; then
            if [ -z "$min_val" ] || [ "$val" -lt "$min_val" ]; then
                min_val="$val"
            fi
        fi
    done

    if [ -z "$min_val" ]; then
        CHECK_DETAIL="TMOUT 설정을 어느 프로파일 파일에서도 찾을 수 없어 세션 자동 종료가 설정되어 있지 않음."
        return "$KISA_EXIT_VULN"
    fi

    if [ "$min_val" -ge 1 ] && [ "$min_val" -le "$TMOUT_LIMIT" ]; then
        CHECK_DETAIL="TMOUT=${min_val}초 로 ${TMOUT_LIMIT}초 이하 기준을 충족함."
        return "$KISA_EXIT_GOOD"
    fi

    CHECK_DETAIL="TMOUT=${min_val}초 로 ${TMOUT_LIMIT}초를 초과함."
    return "$KISA_EXIT_VULN"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
