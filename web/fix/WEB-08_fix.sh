#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-08"
readonly ITEM_TITLE="웹 서비스 파일 업로드 및 다운로드 용량 제한"
readonly ACTION_TAG="자동조치"
readonly IMPACT="업로드/다운로드 최대 용량을 10MB로 제한하며, 이보다 큰 파일을 다루는 서비스가 없다면 영향 없음"
readonly SEVERITY="하"

CHECK_DETAIL=""
FIX_DETAIL=""
declare -a MODIFIED_BACKUPS=()

apache_has_limit() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*LimitRequestBody[[:space:]]+[1-9]' "$f" 2>/dev/null && return 0
    done < <(webdetect_apache_active_confs)
    return 1
}

nginx_has_limit() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*client_max_body_size[[:space:]]' "$f" 2>/dev/null && return 0
    done < <(webdetect_nginx_active_confs)
    return 1
}

do_check() {
    if ! webdetect_any_httpd_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    local vuln="false" detail=""
    if webdetect_apache_present && ! apache_has_limit; then
        vuln="true"; detail="${detail}Apache: LimitRequestBody 없음. "
    fi
    if webdetect_nginx_present && ! nginx_has_limit; then
        vuln="true"; detail="${detail}Nginx: client_max_body_size 없음. "
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

fix_apache() {
    local main
    main="$(webdetect_apache_mainconf 2>/dev/null)" || return 1
    [ -w "$main" ] || return 1
    local backup
    backup="$(webdetect_backup_file "$main")" || return 1
    printf '\n# KISA WEB-08: 업로드/다운로드 용량 제한(기본 10MB)\nLimitRequestBody 10485760\n' >> "$main"
    MODIFIED_BACKUPS+=("${main}::${backup}")
    return 0
}

fix_nginx() {
    local main
    main="$(webdetect_nginx_mainconf 2>/dev/null)" || return 1
    [ -w "$main" ] || return 1
    grep -qE '^[[:space:]]*http[[:space:]]*\{' "$main" || return 1
    local backup
    backup="$(webdetect_backup_file "$main")" || return 1
    sed -i -E '0,/^[[:space:]]*http[[:space:]]*\{/ s/^([[:space:]]*http[[:space:]]*\{)/\1\n    # KISA WEB-08: 업로드\/다운로드 용량 제한(기본 10MB)\n    client_max_body_size 10m;/' "$main"
    MODIFIED_BACKUPS+=("${main}::${backup}")
    return 0
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
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local did_apache="false" did_nginx="false"
    if webdetect_apache_present && ! apache_has_limit; then
        fix_apache && did_apache="true"
    fi
    if webdetect_nginx_present && ! nginx_has_limit; then
        fix_nginx && did_nginx="true"
    fi

    if [ "${#MODIFIED_BACKUPS[@]}" -eq 0 ]; then
        FIX_DETAIL="조치 대상 설정 파일에 쓸 수 없어 조치를 수행하지 못함."
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

    FIX_DETAIL="업로드/다운로드 용량을 10MB로 제한하도록 설정을 추가함. 변경 파일 수: ${#MODIFIED_BACKUPS[@]}"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-08 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
