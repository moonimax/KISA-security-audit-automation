#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-55"
readonly ITEM_TITLE="FTP 계정 shell 제한"
readonly ACTION_TAG="자동조치"
readonly IMPACT="대상 계정의 로그인 셸만 nologin으로 변경되며 서비스 재시작이 불필요함. usermod -s 로 즉시 되돌릴 수 있는 가역적 변경임"
readonly SEVERITY="중"

CHECK_DETAIL=""

_find_user_list() {
    for f in /etc/vsftpd.user_list /etc/vsftpd/user_list /etc/vsftpd/vsftpd.user_list; do
        [ -r "$f" ] && { printf '%s' "$f"; return 0; }
    done
    return 1
}

do_check() {
    local ulist
    ulist="$(_find_user_list)" || {
        CHECK_DETAIL="vsftpd 사용자 목록 파일을 찾을 수 없어 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    }
    if [ ! -r /etc/passwd ]; then
        CHECK_DETAIL="/etc/passwd 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi

    local offenders=()
    while IFS= read -r acct; do
        acct="$(printf '%s' "$acct" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        [ -z "$acct" ] && continue
        [[ "$acct" == \#* ]] && continue
        local shell
        shell="$(awk -F: -v a="$acct" '$1==a{print $7}' /etc/passwd)"
        [ -z "$shell" ] && continue
        [[ "$shell" =~ (nologin|false)$ ]] || offenders+=("${acct}(${shell})")
    done < "$ulist"

    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="${ulist} 에 명시된 계정 중 대화형 셸을 가진 계정 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="${ulist} 에 명시된 모든 계정이 nologin/false 셸을 사용 중임."
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
