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
FIX_DETAIL=""
declare -a MODIFIED_BACKUPS=()

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
                *'<Directory'*) path="$(printf '%s' "$line" | sed -n 's/.*<Directory[[:space:]]*"\{0,1\}\([^">]*\)"\{0,1\}>.*/\1/p')" ;;
                *'</Directory>'*) path="" ;;
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
    if webdetect_apache_present && apache_cgi_module_loaded && apache_execcgi_outside_cgibin; then
        vuln="true"; detail="${detail}Apache: cgi-bin 외부에도 ExecCGI 허용됨. "
    fi
    if webdetect_nginx_present && nginx_fastcgi_present; then
        vuln="true"; detail="${detail}Nginx: fastcgi_pass 존재. "
    fi
    CHECK_DETAIL="${detail:-설정 양호}"
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

fix_apache_file() {
    local f="$1" path line tmp changed="false"
    tmp="$(mktemp)" || return 1
    path=""
    while IFS= read -r line; do
        case "$line" in
            *'<Directory'*) path="$(printf '%s' "$line" | sed -n 's/.*<Directory[[:space:]]*"\{0,1\}\([^">]*\)"\{0,1\}>.*/\1/p')" ;;
            *'</Directory>'*) path="" ;;
        esac
        if printf '%s' "$line" | grep -qiE '^[[:space:]]*Options([[:space:]]|$)' && printf '%s' "$line" | grep -qi 'ExecCGI'; then
            case "$path" in
                *cgi-bin*) : ;;
                *)
                    line="$(printf '%s' "$line" | sed -E 's/(^|[[:space:]])\+?ExecCGI([[:space:]]|$)/\1\2/gI' | sed -E 's/[[:space:]]+/ /g' | sed -E 's/[[:space:]]*$//')"
                    changed="true"
                    ;;
            esac
        fi
        printf '%s\n' "$line"
    done < "$f" > "$tmp"
    if [ "$changed" = "true" ]; then
        local backup
        if backup="$(webdetect_backup_file "$f")"; then
            mv "$tmp" "$f"
            MODIFIED_BACKUPS+=("${f}::${backup}")
            return 0
        fi
    fi
    rm -f "$tmp"
    return 1
}

fix_apache() {
    local f any="false"
    while IFS= read -r f; do
        [ -r "$f" ] && [ -w "$f" ] || continue
        fix_apache_file "$f" && any="true"
    done < <(webdetect_apache_active_confs)
    [ "$any" = "true" ]
}

fix_nginx() {
    local f changed="false"
    while IFS= read -r f; do
        [ -r "$f" ] && [ -w "$f" ] || continue
        grep -qE '^[[:space:]]*fastcgi_pass[[:space:]]' "$f" 2>/dev/null || continue
        local backup
        backup="$(webdetect_backup_file "$f")" || continue
        sed -i -E 's/^([[:space:]]*)(fastcgi_pass[[:space:]].*)$/\1#\2/' "$f"
        MODIFIED_BACKUPS+=("${f}::${backup}")
        changed="true"
    done < <(webdetect_nginx_active_confs)
    [ "$changed" = "true" ]
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): CGI/fastcgi 비활성화는 이를 사용하는 기능을 중단시킬 수 있음. 승인 후 KISA_APPROVAL=true 로 재실행하세요."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local did_apache="false" did_nginx="false"
    webdetect_apache_present && fix_apache && did_apache="true"
    webdetect_nginx_present && fix_nginx && did_nginx="true"

    if [ "${#MODIFIED_BACKUPS[@]}" -eq 0 ]; then
        FIX_DETAIL="조치 대상 설정을 찾지 못해 조치를 수행하지 못함(수동 확인 필요)."
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

    FIX_DETAIL="cgi-bin 외부의 ExecCGI 및 Nginx fastcgi_pass 설정을 제한함. 변경 파일 수: ${#MODIFIED_BACKUPS[@]}"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-05 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
