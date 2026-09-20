#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-19"
readonly ITEM_TITLE="웹 서비스 SSI(Server Side Includes) 사용 제한"
readonly ACTION_TAG="자동조치"
readonly IMPACT="SSI 기능만 비활성화하며, 실제로 SSI 를 사용하는 페이지가 없다면 영향 없음"
readonly SEVERITY="중"

CHECK_DETAIL=""
FIX_DETAIL=""
declare -a MODIFIED_BACKUPS=()

apache_ssi_enabled() {
    local f optline tok
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        while IFS= read -r optline; do
            for tok in $optline; do
                case "$tok" in
                    Includes|+Includes|IncludesNOEXEC|+IncludesNOEXEC) return 0 ;;
                esac
            done
        done < <(grep -iE '^[[:space:]]*Options([[:space:]]|$)' "$f" 2>/dev/null)
    done < <(webdetect_apache_active_confs)
    return 1
}
nginx_ssi_on() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*ssi[[:space:]]+on[[:space:]]*;' "$f" 2>/dev/null && return 0
    done < <(webdetect_nginx_active_confs)
    return 1
}

do_check() {
    if ! webdetect_apache_present && ! webdetect_nginx_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    local vuln="false" detail=""
    webdetect_apache_present && apache_ssi_enabled && { vuln="true"; detail="${detail}Apache SSI 활성화. "; }
    webdetect_nginx_present && nginx_ssi_on && { vuln="true"; detail="${detail}Nginx ssi on. "; }
    CHECK_DETAIL="${detail:-SSI 비활성화됨}"
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
        grep -iE '^[[:space:]]*Options([[:space:]]|$)' "$f" 2>/dev/null | grep -qiE '(^|[[:space:]])\+?Includes(NOEXEC)?([[:space:]]|$)' || continue
        local backup
        backup="$(webdetect_backup_file "$f")" || continue
        sed -i -E '/^[[:space:]]*Options([[:space:]]|$)/ s/(^|[[:space:]])\+?IncludesNOEXEC([[:space:]]|$)/\1\2/gI; /^[[:space:]]*Options([[:space:]]|$)/ s/(^|[[:space:]])\+?Includes([[:space:]]|$)/\1\2/gI' "$f"
        MODIFIED_BACKUPS+=("${f}::${backup}")
        any="true"
    done < <(webdetect_apache_active_confs)
    [ "$any" = "true" ]
}

fix_nginx() {
    local f any="false"
    while IFS= read -r f; do
        [ -r "$f" ] && [ -w "$f" ] || continue
        grep -qiE '^[[:space:]]*ssi[[:space:]]+on[[:space:]]*;' "$f" 2>/dev/null || continue
        local backup
        backup="$(webdetect_backup_file "$f")" || continue
        sed -i -E 's/^([[:space:]]*)ssi[[:space:]]+on[[:space:]]*;/\1ssi off;/I' "$f"
        MODIFIED_BACKUPS+=("${f}::${backup}")
        any="true"
    done < <(webdetect_nginx_active_confs)
    [ "$any" = "true" ]
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
    webdetect_apache_present && apache_ssi_enabled && fix_apache && did_apache="true"
    webdetect_nginx_present && nginx_ssi_on && fix_nginx && did_nginx="true"

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

    FIX_DETAIL="SSI 사용 설정을 비활성화함. 변경 파일 수: ${#MODIFIED_BACKUPS[@]}"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-19 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
