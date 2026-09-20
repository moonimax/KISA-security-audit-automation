#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-18"
readonly ITEM_TITLE="웹 서비스 WebDAV 비활성화"
readonly ACTION_TAG="자동조치"
readonly IMPACT="WebDAV 기능만 비활성화하며, 이를 실제로 사용 중인 경우가 아니라면 영향 없음"
readonly SEVERITY="상"

CHECK_DETAIL=""

apache_dav_on() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*Dav[[:space:]]+On' "$f" 2>/dev/null && return 0
    done < <(webdetect_apache_active_confs)
    return 1
}

nginx_dav_methods_present() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*dav_methods[[:space:]]' "$f" 2>/dev/null && return 0
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
        if apache_dav_on; then
            vuln="true"; detail="${detail}Apache: 'Dav On' 설정으로 WebDAV 가 활성화되어 있음. "
        else
            detail="${detail}Apache: WebDAV 비활성화됨. "
        fi
    fi

    if webdetect_nginx_present; then
        if nginx_dav_methods_present; then
            vuln="true"; detail="${detail}Nginx: dav_methods 설정으로 WebDAV 가 활성화되어 있음. "
        else
            detail="${detail}Nginx: WebDAV 비활성화됨. "
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
