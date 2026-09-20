#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-22"
readonly ITEM_TITLE="에러 페이지 관리"
readonly ACTION_TAG="자동조치"
readonly IMPACT="사용자 지정 에러 페이지를 추가하며 일반적인 경우 서비스 영향 없음"
readonly SEVERITY="하"

CHECK_DETAIL=""
FIX_DETAIL=""
declare -a MODIFIED_BACKUPS=()

ERROR_PAGE_BODY='<!DOCTYPE html><html><head><title>Error</title></head><body><h1>요청을 처리할 수 없습니다</h1><p>잠시 후 다시 시도해 주세요.</p></body></html>'

apache_error_page_present() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*ErrorDocument[[:space:]]' "$f" 2>/dev/null && return 0
    done < <(webdetect_apache_active_confs)
    return 1
}
nginx_error_page_present() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*error_page[[:space:]]' "$f" 2>/dev/null && return 0
    done < <(webdetect_nginx_active_confs)
    return 1
}

do_check() {
    if ! webdetect_apache_present && ! webdetect_nginx_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    local vuln="false" detail=""
    webdetect_apache_present && ! apache_error_page_present && { vuln="true"; detail="${detail}Apache 미설정. "; }
    webdetect_nginx_present && ! nginx_error_page_present && { vuln="true"; detail="${detail}Nginx 미설정. "; }
    CHECK_DETAIL="${detail:-에러 페이지 설정됨}"
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
    local main docroot pagepath
    main="$(webdetect_apache_mainconf 2>/dev/null)" || return 1
    [ -w "$main" ] || return 1
    docroot="$(webdetect_apache_docroot)"
    pagepath="${docroot%/}/kisa_error.html"
    mkdir -p "$docroot" 2>/dev/null
    printf '%s\n' "$ERROR_PAGE_BODY" > "$pagepath" 2>/dev/null || return 1
    local backup
    backup="$(webdetect_backup_file "$main")" || return 1
    {
        printf '\n# KISA WEB-22: 통합 에러 페이지\n'
        printf 'ErrorDocument 404 /kisa_error.html\n'
        printf 'ErrorDocument 500 /kisa_error.html\n'
        printf 'ErrorDocument 502 /kisa_error.html\n'
        printf 'ErrorDocument 503 /kisa_error.html\n'
    } >> "$main"
    MODIFIED_BACKUPS+=("${main}::${backup}")
    return 0
}

fix_nginx() {
    local main ndocroot pagepath
    main="$(webdetect_nginx_mainconf 2>/dev/null)" || return 1
    [ -w "$main" ] || return 1
    grep -qE '^[[:space:]]*http[[:space:]]*\{' "$main" || return 1
    ndocroot="$(webdetect_nginx_docroot)"
    pagepath="${ndocroot%/}/kisa_error.html"
    mkdir -p "$ndocroot" 2>/dev/null
    printf '%s\n' "$ERROR_PAGE_BODY" > "$pagepath" 2>/dev/null || return 1
    local backup
    backup="$(webdetect_backup_file "$main")" || return 1
    sed -i -E '0,/^[[:space:]]*http[[:space:]]*\{/ s#^([[:space:]]*http[[:space:]]*\{)#\1\n    error_page 404 500 502 503 504 /kisa_error.html;#' "$main"
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
    webdetect_apache_present && ! apache_error_page_present && fix_apache && did_apache="true"
    webdetect_nginx_present && ! nginx_error_page_present && fix_nginx && did_nginx="true"

    if [ "${#MODIFIED_BACKUPS[@]}" -eq 0 ]; then
        FIX_DETAIL="설정 파일 또는 문서 루트에 쓸 수 없어 조치를 수행하지 못함."
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

    FIX_DETAIL="버전 정보가 없는 통합 에러 페이지(kisa_error.html)를 생성하고 404/500/502/503/504 에 연결함. 변경 파일 수: ${#MODIFIED_BACKUPS[@]}"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-22 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
