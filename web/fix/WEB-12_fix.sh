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
FIX_DETAIL=""
declare -a MODIFIED_BACKUPS=()

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
    webdetect_apache_present && apache_symlinks_unrestricted && { vuln="true"; detail="${detail}Apache: FollowSymLinks 무제한 허용. "; }
    if webdetect_nginx_present && ! nginx_disable_symlinks_present; then
        vuln="true"; detail="${detail}Nginx: disable_symlinks 없음. "
    fi
    CHECK_DETAIL="${detail:-링크 사용 제한됨}"
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
    local f any="false"
    while IFS= read -r f; do
        [ -r "$f" ] && [ -w "$f" ] || continue
        grep -iE '^[[:space:]]*Options([[:space:]]|$)' "$f" 2>/dev/null | grep -qiE '(^|[[:space:]])\+?FollowSymLinks([[:space:]]|$)' || continue
        local backup
        backup="$(webdetect_backup_file "$f")" || continue
        sed -i -E '/^[[:space:]]*Options([[:space:]]|$)/ {
            s/(^|[[:space:]])\+FollowSymLinks([[:space:]]|$)/\1+SymLinksIfOwnerMatch\2/gI
            s/(^|[[:space:]])FollowSymLinks([[:space:]]|$)/\1SymLinksIfOwnerMatch\2/gI
        }' "$f"
        MODIFIED_BACKUPS+=("${f}::${backup}")
        any="true"
    done < <(webdetect_apache_active_confs)
    [ "$any" = "true" ]
}

fix_nginx() {
    local main
    main="$(webdetect_nginx_mainconf 2>/dev/null)" || return 1
    [ -w "$main" ] || return 1
    grep -qE '^[[:space:]]*http[[:space:]]*\{' "$main" || return 1
    local backup
    backup="$(webdetect_backup_file "$main")" || return 1
    sed -i -E '0,/^[[:space:]]*http[[:space:]]*\{/ s/^([[:space:]]*http[[:space:]]*\{)/\1\n    # KISA WEB-12: 심볼릭 링크 사용 제한\n    disable_symlinks on;/' "$main"
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

    if ! is_approved; then
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 심볼릭 링크로 구성된 사이트가 있다면 조치 후 해당 서비스가 중단될 수 있음. 승인 후 KISA_APPROVAL=true 로 재실행하세요."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local did_apache="false" did_nginx="false"
    webdetect_apache_present && apache_symlinks_unrestricted && fix_apache && did_apache="true"
    if webdetect_nginx_present && ! nginx_disable_symlinks_present; then
        fix_nginx && did_nginx="true"
    fi

    if [ "${#MODIFIED_BACKUPS[@]}" -eq 0 ]; then
        FIX_DETAIL="조치 대상 설정을 찾지 못해 조치를 수행하지 못함."
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

    FIX_DETAIL="심볼릭 링크 사용을 제한함(Apache: SymLinksIfOwnerMatch, Nginx: disable_symlinks on). 심볼릭 링크로 구성된 콘텐츠가 있다면 재점검 필요. 변경 파일 수: ${#MODIFIED_BACKUPS[@]}"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-12 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
