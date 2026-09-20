#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-27"
readonly ITEM_TITLE="\$HOME/.rhosts, hosts.equiv 사용 금지"
readonly ACTION_TAG="승인요청"
readonly IMPACT="파일을 즉시 삭제(rm)하지 않고 .disabled 로 이름을 바꿔 신뢰 기반 인증 기능만 무력화하는 가역적 조치이나, 극히 드물게 정상적인 클러스터/HPC 환경에서 r-계열 트러스트를 의도적으로 사용 중일 수 있어 관리자 확인이 필요함"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    if [ ! -r /etc/passwd ]; then
        CHECK_DETAIL="/etc/passwd 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    local rhosts_found=()
    while IFS=: read -r uname _ _ _ _ home _; do
        [ -z "$home" ] && continue
        [ -e "${home}/.rhosts" ] && rhosts_found+=("${home}/.rhosts(${uname})")
    done < /etc/passwd

    local equiv_bad=""
    if [ -e /etc/hosts.equiv ]; then
        if grep -vE '^[[:space:]]*(#|$)' /etc/hosts.equiv >/dev/null 2>&1; then
            equiv_bad="/etc/hosts.equiv(내용 존재)"
        fi
    fi

    if [ "${#rhosts_found[@]}" -gt 0 ] || [ -n "$equiv_bad" ]; then
        local parts=()
        [ "${#rhosts_found[@]}" -gt 0 ] && parts+=("$(IFS=','; echo "${rhosts_found[*]}")")
        [ -n "$equiv_bad" ] && parts+=("$equiv_bad")
        CHECK_DETAIL="신뢰 기반 인증 파일 발견: $(IFS='; '; echo "${parts[*]}")"
        return "$KISA_EXIT_VULN"
    fi

    CHECK_DETAIL=".rhosts 파일이 존재하는 계정이 없고, hosts.equiv 도 없거나 비어있음(주석 제외)."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
