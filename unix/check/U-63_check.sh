#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-63"
readonly ITEM_TITLE="sudo 명령어 접근 관리"
readonly ACTION_TAG="승인요청"
readonly IMPACT="/etc/sudoers 는 문법 오류 시 시스템 전체의 sudo 권한이 마비될 수 있는 매우 민감한 파일이며, NOPASSWD:ALL 규칙을 가진 계정이 실제로 필요한 자동화 계정인지 관리자 판단이 필요해 승인이 필요함"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    [ -e /etc/sudoers ] || { CHECK_DETAIL="/etc/sudoers가 없어 판정 불가능."; return "$KISA_EXIT_FAIL"; }
    local owner perm u g o reasons=()
    owner="$(stat -L -c '%U' /etc/sudoers 2>/dev/null)"; perm="$(stat -L -c '%a' /etc/sudoers 2>/dev/null)"
    [ -n "$owner" ] && [ -n "$perm" ] || { CHECK_DETAIL="/etc/sudoers 메타정보 확인 실패."; return "$KISA_EXIT_FAIL"; }
    u="${perm: -3:1}"; g="${perm: -2:1}"; o="${perm: -1}"
    [ "$owner" = root ] || reasons+=("소유자=$owner(root 필요)")
    { [ "$u" -le 6 ] && [ "$g" -le 4 ] && [ "$o" -eq 0 ]; } || reasons+=("권한=$perm(640 이하 필요)")
    local f
    if [ -d /etc/sudoers.d ]; then
        while IFS= read -r -d '' f; do
            owner="$(stat -L -c '%U' "$f" 2>/dev/null)"
            perm="$(stat -L -c '%a' "$f" 2>/dev/null)"
            [ -n "$owner" ] && [ -n "$perm" ] || { reasons+=("${f}: 메타정보 확인 실패"); continue; }
            u="${perm: -3:1}"; g="${perm: -2:1}"; o="${perm: -1}"
            [ "$owner" = root ] || reasons+=("${f}: 소유자=$owner")
            { [ "$u" -le 6 ] && [ "$g" -le 4 ] && [ "$o" -eq 0 ]; } || reasons+=("${f}: 권한=$perm")
        done < <(find /etc/sudoers.d -maxdepth 1 -type f -print0 2>/dev/null)
    fi
    local nopasswd_all
    nopasswd_all="$(grep -RhE '^[[:space:]]*[^#%[:space:]][^[:space:]]*[[:space:]]+ALL[[:space:]]*=.*NOPASSWD:[[:space:]]*ALL([[:space:]]|$)' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -n 10)"
    [ -z "$nopasswd_all" ] || reasons+=("일반 계정 NOPASSWD:ALL 규칙 존재: $(printf '%s' "$nopasswd_all" | tr '\n' '|')")
    if [ "${#reasons[@]}" -gt 0 ]; then CHECK_DETAIL="$(IFS='; '; echo "${reasons[*]}")"; return "$KISA_EXIT_VULN"; fi
    CHECK_DETAIL="sudoers 본문/조각 파일의 소유권·권한이 기준을 충족하고 일반 계정 NOPASSWD:ALL 규칙이 없음."; return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
