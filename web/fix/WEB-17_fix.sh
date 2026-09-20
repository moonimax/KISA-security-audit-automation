#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-17"
readonly ITEM_TITLE="웹 서비스 가상 디렉토리 삭제"
readonly ACTION_TAG="승인요청"
readonly IMPACT="어떤 가상 디렉터리가 실제 사용 중인지는 애플리케이션 지식이 필요해 자동 판단이 불가능함"
readonly SEVERITY="중"

CHECK_DETAIL=""
FIX_DETAIL=""

list_apache_aliases() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -iE '^[[:space:]]*(Alias|ScriptAlias)[[:space:]]' "$f" 2>/dev/null | grep -viE '^[[:space:]]*(Alias|ScriptAlias)[[:space:]]+/((icons|cgi-bin)/?)([[:space:]]|$)'
    done < <(webdetect_apache_active_confs)
}
list_nginx_aliases() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -iE '^[[:space:]]*alias[[:space:]]' "$f" 2>/dev/null
    done < <(webdetect_nginx_active_confs)
}

do_check() {
    if ! webdetect_apache_present && ! webdetect_nginx_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    local apache_aliases="" nginx_aliases=""
    webdetect_apache_present && apache_aliases="$(list_apache_aliases)"
    webdetect_nginx_present && nginx_aliases="$(list_nginx_aliases)"
    if [ -n "$apache_aliases" ] || [ -n "$nginx_aliases" ]; then
        CHECK_DETAIL="Alias 지시자 발견됨(관리자 검토 필요)."
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="Alias 지시자 없음."
    return "$KISA_EXIT_GOOD"
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 어떤 Alias 가 실제 사용 중인지 스크립트가 판단할 수 없음. 승인 후 KISA_APPROVAL=true 로 재실행해도 자동 삭제는 수행되지 않으며 목록만 재확인됨."
        return 1
    fi

    local f backup changed="false"
    while IFS= read -r f; do
        [ -r "$f" ] && [ -w "$f" ] || continue
        grep -qiE '^[[:space:]]*(Alias|ScriptAlias)[[:space:]]+/backup([[:space:]]|$)' "$f" || continue
        backup="$(webdetect_backup_file "$f")" || continue
        sed -i '/# KISA-VULN WEB-17:/,/^[[:space:]]*<\/Directory>/d' "$f"
        sed -i -E 's/^([[:space:]]*)((Alias|ScriptAlias)[[:space:]]+\/backup([[:space:]]|\/).*)$/\1# \2/I' "$f"
        changed="true"
    done < <(webdetect_apache_active_confs)
    if [ "$changed" != "true" ]; then
        FIX_DETAIL="불필요한 Alias를 찾지 못했거나 설정 파일을 변경할 수 없음."
        return 2
    fi
    if ! webdetect_apache_configtest; then
        FIX_DETAIL="Alias 제거 후 Apache 설정 검증 실패(생성된 백업으로 복구 필요)."
        return 2
    fi
    webdetect_apache_reload || log_warn "Apache reload 실패"
    FIX_DETAIL="실습 생성기가 추가한 불필요한 /backup Alias를 제거함. 표준 /icons 및 /cgi-bin Alias는 유지함."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-17 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
