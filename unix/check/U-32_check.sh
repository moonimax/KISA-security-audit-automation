#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-32"
readonly ITEM_TITLE="홈 디렉토리로 지정한 디렉토리의 존재 관리"
readonly ACTION_TAG="자동조치"
readonly IMPACT="존재하지 않는 홈 디렉토리를 생성만 하는 비파괴적 변경으로 서비스 재시작이 불필요함. 기존 데이터를 덮어쓰거나 삭제하지 않음"
readonly SEVERITY="하"

CHECK_DETAIL=""

do_check() {
    if [ ! -r /etc/passwd ]; then
        CHECK_DETAIL="/etc/passwd 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    local offenders=() count=0
    while IFS=: read -r uname _ _ _ _ home shell; do
        [ -z "$home" ] && continue
        [[ "$shell" =~ (nologin|false)$ ]] && continue
        if [ ! -d "$home" ]; then
            count=$((count + 1))
            [ "${#offenders[@]}" -lt 15 ] && offenders+=("${uname}:${home}")
        fi
    done < /etc/passwd

    if [ "$count" -gt 0 ]; then
        CHECK_DETAIL="홈 디렉토리가 존재하지 않는 로그인 가능 계정 ${count}건(최대 15건 표시) 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="로그인 가능한 모든 계정의 홈 디렉토리가 실제로 존재함."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
