#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-21"
readonly ITEM_TITLE="HTTP 리디렉션"
readonly ACTION_TAG="승인요청"
readonly IMPACT="HTTPS 로 강제 전환하므로 TLS 가 정상 동작하지 않는 상태에서 적용하면 서비스 접근이 막힐 수 있음"
readonly SEVERITY="중"

CHECK_DETAIL=""
FIX_DETAIL=""
declare -a MODIFIED_BACKUPS=()

apache_ssl_enabled() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '<VirtualHost[^>]*:443' "$f" 2>/dev/null && grep -qiE '^[[:space:]]*SSLEngine[[:space:]]+on' "$f" 2>/dev/null && return 0
    done < <(webdetect_apache_active_confs)
    return 1
}
nginx_ssl_enabled() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*listen[[:space:]]+.*443[[:space:]]+.*ssl' "$f" 2>/dev/null && return 0
    done < <(webdetect_nginx_active_confs)
    return 1
}
apache_http_redirect_present() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '<VirtualHost[^>]*:80' "$f" 2>/dev/null || continue
        grep -qiE 'Redirect|RewriteRule.*https://' "$f" 2>/dev/null && return 0
    done < <(webdetect_apache_active_confs)
    return 1
}
nginx_http_redirect_present() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*listen[[:space:]]+80' "$f" 2>/dev/null || continue
        grep -qiE 'return[[:space:]]+30[12][[:space:]]+https://' "$f" 2>/dev/null && return 0
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
        if ! apache_ssl_enabled; then vuln="true"; detail="${detail}Apache SSL 미구성(WEB-20 선행 필요). "
        elif ! apache_http_redirect_present; then vuln="true"; detail="${detail}Apache 리디렉션 없음. "
        else detail="${detail}Apache 양호. "; fi
    fi
    if webdetect_nginx_present; then
        if ! nginx_ssl_enabled; then vuln="true"; detail="${detail}Nginx SSL 미구성(WEB-20 선행 필요). "
        elif ! nginx_http_redirect_present; then vuln="true"; detail="${detail}Nginx 리디렉션 없음. "
        else detail="${detail}Nginx 양호. "; fi
    fi
    CHECK_DETAIL="${detail% }"
    [ "$vuln" = "true" ] && return "$KISA_EXIT_VULN"
    return "$KISA_EXIT_GOOD"
}

rollback_modified() {
    local entry orig backup
    for entry in "${MODIFIED_BACKUPS[@]}"; do
        orig="${entry%%::*}"; backup="${entry##*::}"
        cp -p "$backup" "$orig" 2>/dev/null
    done
}

do_fix() {
    do_check
    local current=$?

    if [ "$current" -eq "$KISA_EXIT_GOOD" ]; then
        FIX_DETAIL="이미 양호 상태로 조치가 필요하지 않음."
        return 0
    fi
    if [ "$current" -eq "$KISA_EXIT_FAIL" ]; then
        FIX_DETAIL="조치 대상 상태를 확인할 수 없어 조치를 수행하지 않음."
        return 2
    fi

    if ! is_approved; then
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): SSL 이 정상 동작하지 않는 상태에서 강제 리디렉션 적용 시 서비스 접근이 막힐 수 있음. 승인 후 KISA_APPROVAL=true 로 재실행하세요."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local blocked=""
    if webdetect_apache_present && ! apache_ssl_enabled; then
        blocked="${blocked}Apache(WEB-20 미구성) "
    fi
    if webdetect_nginx_present && ! nginx_ssl_enabled; then
        blocked="${blocked}Nginx(WEB-20 미구성) "
    fi
    if [ -n "$blocked" ]; then
        FIX_DETAIL="다음 서비스는 SSL/TLS(WEB-20)가 먼저 구성되어야 하므로 리디렉션 조치를 수행하지 않음: ${blocked% }. WEB-20 을 먼저 조치한 뒤 재실행하세요."
        return 1
    fi

    local did_apache="false" did_nginx="false"

    if webdetect_apache_present && ! apache_http_redirect_present; then
        local f
        while IFS= read -r f; do
            [ -r "$f" ] && [ -w "$f" ] || continue
            grep -qiE '<VirtualHost[^>]*:80' "$f" 2>/dev/null || continue
            local backup
            backup="$(webdetect_backup_file "$f")" || continue
            sed -i -E 's#(<VirtualHost[^>]*:80>)#\1\n    Redirect permanent / https://%{HTTP_HOST}/#I' "$f"
            MODIFIED_BACKUPS+=("${f}::${backup}")
            did_apache="true"
        done < <(webdetect_apache_active_confs)
    fi

    if webdetect_nginx_present && ! nginx_http_redirect_present; then
        local nf
        while IFS= read -r nf; do
            [ -r "$nf" ] && [ -w "$nf" ] || continue
            grep -qE '^[[:space:]]*listen[[:space:]]+80' "$nf" 2>/dev/null || continue
            local backup
            backup="$(webdetect_backup_file "$nf")" || continue
            sed -i -E '/^[[:space:]]*listen[[:space:]]+80/a\    return 301 https://$host$request_uri;' "$nf"
            MODIFIED_BACKUPS+=("${nf}::${backup}")
            did_nginx="true"
        done < <(webdetect_nginx_active_confs)
    fi

    if [ "${#MODIFIED_BACKUPS[@]}" -eq 0 ]; then
        FIX_DETAIL="80 포트 VirtualHost/server 블록을 찾지 못해 조치를 수행하지 못함."
        return 2
    fi

    local ok="true"
    [ "$did_apache" = "true" ] && ! webdetect_apache_configtest && ok="false"
    [ "$did_nginx" = "true" ] && ! webdetect_nginx_configtest && ok="false"

    if [ "$ok" != "true" ]; then
        rollback_modified
        FIX_DETAIL="변경된 설정이 문법 검증에 실패하여 백업본으로 롤백함."
        return 2
    fi

    [ "$did_apache" = "true" ] && { webdetect_apache_reload || log_warn "Apache reload 실패"; }
    [ "$did_nginx" = "true" ] && { webdetect_nginx_reload || log_warn "Nginx reload 실패"; }

    FIX_DETAIL="80 포트에 HTTPS 강제 리디렉션을 추가함. 변경 파일 수: ${#MODIFIED_BACKUPS[@]}"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-21 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
