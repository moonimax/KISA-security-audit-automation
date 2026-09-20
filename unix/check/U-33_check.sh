#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-33"
readonly ITEM_TITLE="숨겨진 파일 및 디렉토리 검색 및 제거"
readonly ACTION_TAG="승인요청"
readonly IMPACT="탐지된 파일이 실제 악성/은닉 목적인지 정상 애플리케이션의 캐시 파일 등인지는 관리자의 확인이 필요하며, 삭제(rm)는 되돌릴 수 없는 파괴적 변경이라 자동으로 실행하지 않음"
readonly SEVERITY="상"
readonly SCAN_TIMEOUT="${KISA_U33_SCAN_TIMEOUT:-20}"

CHECK_DETAIL=""

_scan_dirs() {
    local dirs=(/tmp /var/tmp /dev/shm)
    local uid_min
    uid_min="$(awk '/^[[:space:]]*UID_MIN[[:space:]]/{print $2; exit}' /etc/login.defs 2>/dev/null)"
    uid_min="${uid_min:-1000}"
    if [ -r /etc/passwd ]; then
        while IFS=: read -r _ _ uid _ _ home shell; do
            { [ "$uid" -eq 0 ] || [ "$uid" -ge "$uid_min" ]; } || continue
            [[ "$shell" =~ (nologin|false)$ ]] && continue
            [ -n "$home" ] && [ "$home" != "/" ] && [ -d "$home" ] && dirs+=("$home")
        done < /etc/passwd
    fi
    printf '%s\n' "${dirs[@]}" | sort -u
}

do_check() {
    if ! command -v find >/dev/null 2>&1; then
        CHECK_DETAIL="find 명령을 찾을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    local dirs
    mapfile -t dirs < <(_scan_dirs)

    local result="" rc=0 f_args=()
    for d in "${dirs[@]}"; do
        [ -d "$d" ] || continue
        f_args+=("$d")
    done

    if [ "${#f_args[@]}" -eq 0 ]; then
        CHECK_DETAIL="점검 대상 디렉토리를 찾을 수 없어 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    if command -v timeout >/dev/null 2>&1; then
        result="$(timeout "$SCAN_TIMEOUT" find "${f_args[@]}" -xdev -maxdepth 3 \
            \( -regex '.*/\.\.+' -o -regex '.*/\. +' -o -name ' ' \) \
            -not -name '.' -not -name '..' -print 2>/dev/null | head -n 20)"
        rc=$?
    else
        result="$(find "${f_args[@]}" -xdev -maxdepth 3 \
            \( -regex '.*/\.\.+' -o -regex '.*/\. +' -o -name ' ' \) \
            -not -name '.' -not -name '..' -print 2>/dev/null | head -n 20)"
    fi

    if [ "$rc" -ne 0 ] && [ "$rc" -ne 141 ]; then
        CHECK_DETAIL="은닉 파일 스캔이 실패하거나 ${SCAN_TIMEOUT}초 내에 끝나지 않아 전체 대상을 확인하지 못함(rc=${rc})."
        return "$KISA_EXIT_FAIL"
    fi

    if [ -n "$result" ]; then
        local count sample
        count="$(printf '%s\n' "$result" | grep -c .)"
        sample="$(printf '%s\n' "$result" | tr '\n' ',' | sed 's/,$//')"
        CHECK_DETAIL="이름을 위장한 은닉 파일/디렉토리 ${count}건(최대 20건 표시) 발견: ${sample}"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL="점검 대상 경로에서 이름을 위장한 은닉 파일을 발견하지 못함."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
