#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-04"
readonly ITEM_TITLE="웹 서비스 디렉터리 리스팅 방지 설정"
readonly ACTION_TAG="자동조치"
readonly IMPACT="디렉터리 목록 노출 기능만 차단하며 일반적인 경우 서비스 영향 없음"
readonly SEVERITY="상"

CHECK_DETAIL=""

apache_indexes_enabled() {
    local f optline tok
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        while IFS= read -r optline; do
            for tok in $optline; do
                case "$tok" in
                    Indexes|+Indexes) return 0 ;;
                esac
            done
        done < <(grep -iE '^[[:space:]]*Options([[:space:]]|$)' "$f" 2>/dev/null)
    done < <(webdetect_apache_active_confs)
    return 1
}

nginx_autoindex_enabled() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -iE '^[[:space:]]*autoindex[[:space:]]+on[[:space:]]*;' "$f" >/dev/null 2>&1 && return 0
    done < <(webdetect_nginx_active_confs)
    return 1
}

do_check() {
    if ! webdetect_any_httpd_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    local vuln="false" detail=""

    if webdetect_apache_present; then
        if apache_indexes_enabled; then
            vuln="true"
            detail="${detail}Apache: Options 지시자에 Indexes 옵션이 활성화되어 디렉터리 리스팅이 노출됨. "
        else
            detail="${detail}Apache: Indexes 옵션 없음. "
        fi
    fi

    if webdetect_nginx_present; then
        if nginx_autoindex_enabled; then
            vuln="true"
            detail="${detail}Nginx: autoindex on 설정으로 디렉터리 리스팅이 노출됨. "
        else
            detail="${detail}Nginx: autoindex off(또는 미설정, 기본값 off). "
        fi
    fi

    CHECK_DETAIL="${detail% }"
    if [ "$vuln" = "true" ]; then
        return "$KISA_EXIT_VULN"
    fi
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
