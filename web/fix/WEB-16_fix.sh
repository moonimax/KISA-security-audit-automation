#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-16"
readonly ITEM_TITLE="웹 서비스 헤더 정보 노출 제한"
readonly ACTION_TAG="자동조치"
readonly IMPACT="응답 헤더의 버전/서버 정보만 숨기며 일반적인 경우 서비스 영향 없음"
readonly SEVERITY="중"

CHECK_DETAIL=""
FIX_DETAIL=""
declare -a MODIFIED_BACKUPS=()

apache_tokens_value() {
    local f last=""
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        local v; v="$(grep -iE '^[[:space:]]*ServerTokens[[:space:]]' "$f" 2>/dev/null | tail -n1 | awk '{print $2}')"
        [ -n "$v" ] && last="$v"
    done < <(webdetect_apache_active_confs)
    printf '%s' "$last"
}
apache_signature_value() {
    local f last=""
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        local v; v="$(grep -iE '^[[:space:]]*ServerSignature[[:space:]]' "$f" 2>/dev/null | tail -n1 | awk '{print $2}')"
        [ -n "$v" ] && last="$v"
    done < <(webdetect_apache_active_confs)
    printf '%s' "$last"
}
nginx_tokens_off() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*server_tokens[[:space:]]+off[[:space:]]*;' "$f" 2>/dev/null && return 0
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
        local tok sig
        tok="$(apache_tokens_value)"; sig="$(apache_signature_value)"
        if [ "$tok" = "Prod" ] && [ "$sig" = "Off" ]; then
            detail="${detail}Apache 양호. "
        else
            vuln="true"; detail="${detail}Apache ServerTokens='${tok:-미설정}' ServerSignature='${sig:-미설정}'. "
        fi
    fi
    if webdetect_nginx_present && ! nginx_tokens_off; then
        vuln="true"; detail="${detail}Nginx server_tokens off 미설정. "
    fi
    CHECK_DETAIL="${detail:-헤더 노출 제한 양호}"
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
    local f changed="false" main
    while IFS= read -r f; do
        [ -r "$f" ] && [ -w "$f" ] || continue
        if grep -qiE '^[[:space:]]*(ServerTokens|ServerSignature)[[:space:]]' "$f"; then
            local backup
            backup="$(webdetect_backup_file "$f")" || continue
            sed -i -E 's/^([[:space:]]*)ServerTokens[[:space:]]+.*/\1ServerTokens Prod/I; s/^([[:space:]]*)ServerSignature[[:space:]]+.*/\1ServerSignature Off/I' "$f"
            MODIFIED_BACKUPS+=("${f}::${backup}")
            changed="true"
        fi
    done < <(webdetect_apache_active_confs)

    if [ "$changed" != "true" ]; then
        main="$(webdetect_apache_mainconf 2>/dev/null)" || return 1
        [ -w "$main" ] || return 1
        local backup
        backup="$(webdetect_backup_file "$main")" || return 1
        printf '\nServerTokens Prod\nServerSignature Off\n' >> "$main"
        MODIFIED_BACKUPS+=("${main}::${backup}")
    fi
    return 0
}

fix_nginx() {
    local main
    main="$(webdetect_nginx_mainconf 2>/dev/null)" || return 1
    [ -w "$main" ] || return 1
    grep -qE '^[[:space:]]*http[[:space:]]*\{' "$main" || return 1
    local backup
    backup="$(webdetect_backup_file "$main")" || return 1
    if grep -qiE '^[[:space:]]*server_tokens[[:space:]]' "$main"; then
        sed -i -E 's/^([[:space:]]*)server_tokens[[:space:]]+.*/\1server_tokens off;/I' "$main"
    else
        sed -i -E '0,/^[[:space:]]*http[[:space:]]*\{/ s/^([[:space:]]*http[[:space:]]*\{)/\1\n    server_tokens off;/' "$main"
    fi
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
    if webdetect_apache_present; then
        local tok sig; tok="$(apache_tokens_value)"; sig="$(apache_signature_value)"
        [ "$tok" = "Prod" ] && [ "$sig" = "Off" ] || { fix_apache && did_apache="true"; }
    fi
    if webdetect_nginx_present && ! nginx_tokens_off; then
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

    FIX_DETAIL="ServerTokens Prod/ServerSignature Off(Apache), server_tokens off(Nginx) 설정을 적용함. 변경 파일 수: ${#MODIFIED_BACKUPS[@]}"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-16 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
