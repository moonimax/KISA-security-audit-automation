#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-06"
readonly ITEM_TITLE="웹 서비스 상위 디렉터리 접근 제한 설정"
readonly ACTION_TAG="승인요청"
readonly IMPACT="웹 서버 및 웹 서비스의 특성에 따라 접근 제어 추가가 정상 접근까지 막을 수 있음"
readonly SEVERITY="상"

CHECK_DETAIL=""

apache_has_access_control() {
    local f in_root_dir="false" found_deny="false" found_root_block="false"
    local line path
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        in_root_dir="false"
        while IFS= read -r line; do
            case "$line" in
                *'<Directory'*)
                    path="$(printf '%s' "$line" | sed -n 's/.*<Directory[[:space:]]*"\{0,1\}\([^">]*\)"\{0,1\}>.*/\1/p')"
                    if [ "$path" = "/" ]; then
                        in_root_dir="true"
                        found_root_block="true"
                    else
                        in_root_dir="false"
                    fi
                    ;;
                *'</Directory>'*)
                    in_root_dir="false"
                    ;;
                *)
                    if [ "$in_root_dir" = "true" ] && printf '%s' "$line" \
                        | grep -qiE '^[[:space:]]*Require[[:space:]]+all[[:space:]]+denied'; then
                        found_deny="true"
                    fi
                    ;;
            esac
        done < "$f"
    done < <(webdetect_apache_active_confs)

    if [ "$found_root_block" = "false" ]; then
        return 1
    fi
    [ "$found_deny" = "true" ]
}

nginx_has_auth_basic() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*auth_basic[[:space:]]' "$f" 2>/dev/null && return 0
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
        if apache_has_access_control; then
            detail="${detail}Apache: Require/AllowOverride AuthConfig 접근 제어 설정 발견. "
        else
            vuln="true"
            detail="${detail}Apache: 설정 전반에서 Require/AllowOverride AuthConfig 접근 제어를 찾지 못함(참고용 판정, 관리자 검토 필요). "
        fi
    fi

    if webdetect_nginx_present; then
        if nginx_has_auth_basic; then
            detail="${detail}Nginx: auth_basic 접근 제어 설정 발견. "
        else
            vuln="true"
            detail="${detail}Nginx: 설정 전반에서 auth_basic 접근 제어를 찾지 못함(참고용 판정, 관리자 검토 필요). "
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
