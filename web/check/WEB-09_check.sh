#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-09"
readonly ITEM_TITLE="웹 서비스 프로세스 권한 제한"
readonly ACTION_TAG="승인요청"
readonly IMPACT="서비스 구동 계정 변경 및 관련 디렉터리 소유권 조정이 필요해 서비스 재시작 및 권한 오류 위험이 있음"
readonly SEVERITY="상"

CHECK_DETAIL=""

do_check() {
    if ! webdetect_any_httpd_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    if ! command -v ps >/dev/null 2>&1; then
        CHECK_DETAIL="ps 명령을 사용할 수 없어 프로세스 실행 계정을 확인할 수 없음."
        return "$KISA_EXIT_FAIL"
    fi

    local vuln="false" detail=""
    local procs
    procs="$(ps -eo comm,user 2>/dev/null)"

    if webdetect_apache_present; then
        local envvars="/etc/apache2/envvars" configured_user=""
        if [ -r "$envvars" ]; then
            configured_user="$(grep -E '^export APACHE_RUN_USER=' "$envvars" 2>/dev/null | tail -n1 | cut -d= -f2-)"
        fi
        if [ "$configured_user" = "root" ]; then
            vuln="true"
            detail="${detail}Apache: APACHE_RUN_USER=root 설정 발견. "
        fi
        local apache_procs apache_nonroot
        apache_procs="$(printf '%s\n' "$procs" | awk '$1=="apache2" || $1=="httpd"')"
        if [ -n "$apache_procs" ]; then
            apache_nonroot="$(printf '%s\n' "$apache_procs" | awk '$2!="root"' | wc -l)"
            if [ "$apache_nonroot" -eq 0 ]; then
                vuln="true"
                detail="${detail}Apache: 모든 프로세스가 root 계정으로 구동 중(워커 분리 없음). "
            else
                detail="${detail}Apache: non-root 워커 프로세스 확인됨. "
            fi
        fi
    fi

    if webdetect_nginx_present; then
        local nginx_procs nginx_nonroot
        nginx_procs="$(printf '%s\n' "$procs" | awk '$1=="nginx"')"
        if [ -n "$nginx_procs" ]; then
            nginx_nonroot="$(printf '%s\n' "$nginx_procs" | awk '$2!="root"' | wc -l)"
            if [ "$nginx_nonroot" -eq 0 ]; then
                vuln="true"
                detail="${detail}Nginx: 모든 프로세스가 root 계정으로 구동 중(워커 분리 없음). "
            else
                detail="${detail}Nginx: non-root 워커 프로세스 확인됨. "
            fi
        fi
    fi

    if [ -z "$detail" ]; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있으나 실행 중인 프로세스를 찾지 못해 판정할 수 없음(서비스 중지 상태로 추정)."
        return "$KISA_EXIT_FAIL"
    fi

    CHECK_DETAIL="${detail% }"
    [ "$vuln" = "true" ] && return "$KISA_EXIT_VULN"
    return "$KISA_EXIT_GOOD"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
