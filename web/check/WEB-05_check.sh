#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-05"
readonly ITEM_TITLE="지정하지 않은 CGI/ISAPI 실행 제한"
readonly ACTION_TAG="승인요청"
readonly IMPACT="CGI 실행 제한/fastcgi 비활성화 시 해당 기능에 의존하는 애플리케이션이 동작하지 않을 수 있음"
readonly SEVERITY="상"

CHECK_DETAIL=""

apache_cgi_module_loaded() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*LoadModule[[:space:]]+cgid?_module' "$f" 2>/dev/null && return 0
    done < <(webdetect_apache_active_confs)
    local ctl
    ctl="$(webdetect_apache_ctl 2>/dev/null)" || return 1
    "$ctl" -M 2>/dev/null | grep -qi 'cgi' && return 0
    return 1
}

apache_execcgi_outside_cgibin() {
    local f path line
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        path=""
        while IFS= read -r line; do
            case "$line" in
                *'<Directory'*)
                    path="$(printf '%s' "$line" | sed -n 's/.*<Directory[[:space:]]*"\{0,1\}\([^">]*\)"\{0,1\}>.*/\1/p')"
                    ;;
                *'</Directory>'*)
                    path=""
                    ;;
            esac
            if printf '%s' "$line" | grep -qiE '^[[:space:]]*Options([[:space:]]|$)' && printf '%s' "$line" | grep -qi 'ExecCGI'; then
                case "$path" in
                    *cgi-bin*) : ;;
                    *) return 0 ;;
                esac
            fi
        done < "$f"
    done < <(webdetect_apache_active_confs)
    return 1
}

nginx_fastcgi_present() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qE '^[[:space:]]*fastcgi_pass[[:space:]]' "$f" 2>/dev/null && return 0
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
        if apache_cgi_module_loaded && apache_execcgi_outside_cgibin; then
            vuln="true"
            detail="${detail}Apache: cgi 모듈이 로드되어 있고 cgi-bin 이외의 디렉터리에도 ExecCGI 가 허용되어 있음. "
        else
            detail="${detail}Apache: CGI 모듈 미사용이거나 cgi-bin 으로만 실행이 제한됨. "
        fi
    fi

    if webdetect_nginx_present; then
        if nginx_fastcgi_present; then
            vuln="true"
            detail="${detail}Nginx: fastcgi_pass 설정이 존재하여 관리자 검토가 필요함. "
        else
            detail="${detail}Nginx: fastcgi_pass 설정 없음. "
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
