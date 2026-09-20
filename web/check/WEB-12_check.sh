#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-12"
readonly ITEM_TITLE="웹 서비스 링크 사용 금지"
readonly ACTION_TAG="승인요청"
readonly IMPACT="심볼릭 링크를 이용하여 웹페이지가 구성된 경우 해당 서비스가 실행되지 않을 수 있음"
readonly SEVERITY="중"

CHECK_DETAIL=""

apache_symlinks_unrestricted() {
    local f optline tok has_follow
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        while IFS= read -r optline; do
            has_follow="false"
            for tok in $optline; do
                case "$tok" in
                    FollowSymLinks|+FollowSymLinks) has_follow="true" ;;
                    SymLinksIfOwnerMatch|+SymLinksIfOwnerMatch) has_follow="false" ;;
                esac
            done
            [ "$has_follow" = "true" ] && return 0
        done < <(grep -iE '^[[:space:]]*Options([[:space:]]|$)' "$f" 2>/dev/null)
    done < <(webdetect_apache_active_confs)
    return 1
}

nginx_disable_symlinks_present() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*disable_symlinks[[:space:]]' "$f" 2>/dev/null && return 0
    done < <(webdetect_nginx_active_confs)
    return 1
}

do_check() {
    if ! webdetect_apache_present && ! webdetect_nginx_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    local vuln="false" detail=""

    if webdetect_apache_present; then
        if apache_symlinks_unrestricted; then
            vuln="true"
            detail="${detail}Apache: Options FollowSymLinks 가 SymLinksIfOwnerMatch 로 제한되지 않고 허용됨. "
        else
            detail="${detail}Apache: 심볼릭 링크 사용이 제한됨(또는 미사용). "
        fi
    fi

    if webdetect_nginx_present; then
        if nginx_disable_symlinks_present; then
            detail="${detail}Nginx: disable_symlinks 설정 확인됨. "
        else
            vuln="true"
            detail="${detail}Nginx: disable_symlinks 설정 없음(기본값 = 제한 없음). "
        fi
    fi

    CHECK_DETAIL="${detail% }"
    [ "$vuln" = "true" ] && return "$KISA_EXIT_VULN"
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
