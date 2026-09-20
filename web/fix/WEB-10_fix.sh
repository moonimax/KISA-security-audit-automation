#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-10"
readonly ITEM_TITLE="불필요한 프록시 설정 제한"
readonly ACTION_TAG="승인요청"
readonly IMPACT="정방향 프록시 기능을 비활성화하며, 이를 실제로 사용 중인 경우가 아니라면 영향 없음"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""
declare -a MODIFIED_BACKUPS=()

apache_open_proxy_enabled() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*ProxyRequests[[:space:]]+On' "$f" 2>/dev/null && return 0
    done < <(webdetect_apache_active_confs)
    return 1
}

do_check() {
    if ! webdetect_apache_present && ! webdetect_nginx_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    if webdetect_apache_present && apache_open_proxy_enabled; then
        CHECK_DETAIL="ProxyRequests On 활성화됨."
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="정방향 프록시 설정 없음."
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 정방향 프록시 비활성화가 실제로는 필요한 구성일 수 있음. 승인 후 KISA_APPROVAL=true 로 재실행하세요."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local f any="false"
    while IFS= read -r f; do
        [ -r "$f" ] && [ -w "$f" ] || continue
        grep -qiE '^[[:space:]]*ProxyRequests[[:space:]]+On' "$f" 2>/dev/null || continue
        local backup
        backup="$(webdetect_backup_file "$f")" || continue
        sed -i -E 's/^([[:space:]]*)(ProxyRequests[[:space:]]+On.*)$/\1#\2/I' "$f"
        MODIFIED_BACKUPS+=("${f}::${backup}")
        any="true"
    done < <(webdetect_apache_active_confs)

    if [ "$any" != "true" ]; then
        FIX_DETAIL="조치 대상 설정을 찾지 못해 조치를 수행하지 못함."
        return 2
    fi

    if ! webdetect_apache_configtest; then
        rollback_modified
        FIX_DETAIL="변경된 설정이 문법 검증에 실패하여 백업본으로 롤백함."
        return 2
    fi

    webdetect_apache_reload || log_warn "Apache reload 실패"
    FIX_DETAIL="ProxyRequests On 설정을 주석 처리하여 정방향(오픈) 프록시를 비활성화함. 변경 파일 수: ${#MODIFIED_BACKUPS[@]}"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-10 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
