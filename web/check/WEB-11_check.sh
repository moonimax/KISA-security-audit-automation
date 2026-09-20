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
CHECK_EVIDENCE=""

is_shared_system_path() {
    case "$1" in
        "/"|"/usr"|"/usr/"|"/etc"|"/etc/"|"/home"|"/home/"|"/root"|"/root/"|"/var"|"/var/"|"/"|"") return 0 ;;
        *) return 1 ;;
    esac
}

do_check() {
    if ! webdetect_apache_present && ! webdetect_nginx_present; then
        CHECK_EVIDENCE="$(evidence_json "웹 서버" "Apache/Nginx 미설치")"
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi

    local vuln="false" detail="" apache_root="해당 없음" nginx_root="해당 없음"

    if webdetect_apache_present; then
        local root
        root="$(webdetect_apache_docroot)"
        apache_root="${root:-미설정}"
        if is_shared_system_path "$root"; then
            vuln="true"
            detail="${detail}Apache DocumentRoot='${root}'(공용 시스템 경로로 추정). "
        else
            detail="${detail}Apache DocumentRoot='${root}'(전용 경로). "
        fi
    fi

    if webdetect_nginx_present; then
        local nroot
        nroot="$(webdetect_nginx_docroot)"
        nginx_root="${nroot:-미설정}"
        if is_shared_system_path "$nroot"; then
            vuln="true"
            detail="${detail}Nginx root='${nroot}'(공용 시스템 경로로 추정). "
        else
            detail="${detail}Nginx root='${nroot}'(전용 경로). "
        fi
    fi

    CHECK_EVIDENCE="$(evidence_json "Apache DocumentRoot" "$apache_root" "Nginx root" "$nginx_root")"
    if [ "$vuln" = "true" ]; then
        CHECK_DETAIL="[관리자 수동 조치 필요] ${detail% } (참고: 이 판정은 경로 문자열 기반 휴리스틱이며 실제 업무 분리 여부는 관리자 확인이 필요함 — 자동/승인조치로 처리되지 않는 항목)"
    else
        CHECK_DETAIL="${detail% } (참고: 이 판정은 경로 문자열 기반 휴리스틱이며 실제 업무 분리 여부는 관리자 확인이 필요함)"
    fi
    [ "$vuln" = "true" ] && return "$KISA_EXIT_VULN"
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY" "$CHECK_EVIDENCE"
