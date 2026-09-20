#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-11"
readonly ITEM_TITLE="웹 서비스 경로 설정"
readonly ACTION_TAG="승인요청"
readonly IMPACT="DocumentRoot 이전 시 기존 콘텐츠 이관이 선행되어야 하며, 하지 않으면 서비스 중단됨"
readonly SEVERITY="중"

CHECK_DETAIL=""
FIX_DETAIL=""

is_shared_system_path() {
    case "$1" in
        "/"|"/usr"|"/usr/"|"/etc"|"/etc/"|"/home"|"/home/"|"/root"|"/root/"|"/var"|"/var/"|"") return 0 ;;
        *) return 1 ;;
    esac
}

do_check() {
    if ! webdetect_apache_present && ! webdetect_nginx_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    local vuln="false" detail=""
    if webdetect_apache_present; then
        local root; root="$(webdetect_apache_docroot)"
        is_shared_system_path "$root" && { vuln="true"; detail="${detail}Apache DocumentRoot='${root}'. "; }
    fi
    if webdetect_nginx_present; then
        local nroot; nroot="$(webdetect_nginx_docroot)"
        is_shared_system_path "$nroot" && { vuln="true"; detail="${detail}Nginx root='${nroot}'. "; }
    fi
    CHECK_DETAIL="${detail:-경로 양호}"
    [ "$vuln" = "true" ] && return "$KISA_EXIT_VULN"
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): DocumentRoot 이전은 콘텐츠 이관이 선행되어야 함. 승인 후 KISA_APPROVAL=true 로 재실행해도 자동 변경은 수행되지 않으며, 아래 안내에 따라 수동으로 이전해야 함."
        return 1
    fi

    FIX_DETAIL="이 항목은 콘텐츠 손실/서비스 중단 위험이 있어 자동화하지 않음. 웹 서비스 콘텐츠를 /var/www/<서비스명> 과 같은 전용 하위 경로로 옮긴 뒤, Apache 는 DocumentRoot, Nginx 는 root 지시자를 새 경로로 수정하고 재구동해야 함. 시스템 변경 없이 안내만 반환함."
    return 1
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-11 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
