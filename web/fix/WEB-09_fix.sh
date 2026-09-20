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
FIX_DETAIL=""

do_check() {
    if ! webdetect_any_httpd_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    command -v ps >/dev/null 2>&1 || { CHECK_DETAIL="ps 명령을 사용할 수 없음."; return "$KISA_EXIT_FAIL"; }

    local vuln="false" detail="" procs
    procs="$(ps -eo comm,user 2>/dev/null)"

    if webdetect_apache_present; then
        local envvars="/etc/apache2/envvars" configured_user=""
        if [ -r "$envvars" ]; then
            configured_user="$(grep -E '^export APACHE_RUN_USER=' "$envvars" 2>/dev/null | tail -n1 | cut -d= -f2-)"
        fi
        if [ "$configured_user" = "root" ]; then
            vuln="true"; detail="${detail}Apache: APACHE_RUN_USER=root 설정 발견. "
        fi
        local ap non
        ap="$(printf '%s\n' "$procs" | awk '$1=="apache2" || $1=="httpd"')"
        if [ -n "$ap" ]; then
            non="$(printf '%s\n' "$ap" | awk '$2!="root"' | wc -l)"
            [ "$non" -eq 0 ] && { vuln="true"; detail="${detail}Apache: root 로만 구동. "; } || detail="${detail}Apache: non-root 워커 있음. "
        fi
    fi
    if webdetect_nginx_present; then
        local np non2
        np="$(printf '%s\n' "$procs" | awk '$1=="nginx"')"
        if [ -n "$np" ]; then
            non2="$(printf '%s\n' "$np" | awk '$2!="root"' | wc -l)"
            [ "$non2" -eq 0 ] && { vuln="true"; detail="${detail}Nginx: root 로만 구동. "; } || detail="${detail}Nginx: non-root 워커 있음. "
        fi
    fi
    if [ -z "$detail" ]; then
        CHECK_DETAIL="실행 중인 프로세스를 찾지 못해 판정 불가."
        return "$KISA_EXIT_FAIL"
    fi
    CHECK_DETAIL="${detail% }"
    [ "$vuln" = "true" ] && return "$KISA_EXIT_VULN"
    return "$KISA_EXIT_GOOD"
}

fix_apache_user() {
    local envvars="/etc/apache2/envvars"
    id -u www-data >/dev/null 2>&1 || return 1
    [ -w "$envvars" ] || return 1
    local backup
    backup="$(webdetect_backup_file "$envvars")" || return 1
    sed -i -E 's/^export APACHE_RUN_USER=.*/export APACHE_RUN_USER=www-data/' "$envvars"
    sed -i -E 's/^export APACHE_RUN_GROUP=.*/export APACHE_RUN_GROUP=www-data/' "$envvars"
    grep -q '^export APACHE_RUN_USER=' "$envvars" || printf 'export APACHE_RUN_USER=www-data\n' >> "$envvars"
    grep -q '^export APACHE_RUN_GROUP=' "$envvars" || printf 'export APACHE_RUN_GROUP=www-data\n' >> "$envvars"
    MODIFIED_BACKUPS+=("${envvars}::${backup}")
    return 0
}

fix_nginx_user() {
    local main runuser
    main="$(webdetect_nginx_mainconf 2>/dev/null)" || return 1
    [ -w "$main" ] || return 1
    if id -u nginx >/dev/null 2>&1; then runuser="nginx"; elif id -u www-data >/dev/null 2>&1; then runuser="www-data"; else return 1; fi
    local backup
    backup="$(webdetect_backup_file "$main")" || return 1
    if grep -qE '^[[:space:]]*user[[:space:]]' "$main"; then
        sed -i -E "s/^([[:space:]]*)user[[:space:]]+.*;/\1user ${runuser};/" "$main"
    else
        sed -i "1i user ${runuser};" "$main"
    fi
    MODIFIED_BACKUPS+=("${main}::${backup}")
    return 0
}

declare -a MODIFIED_BACKUPS=()

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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 서비스 구동 계정 변경은 파일 접근 권한 오류를 유발할 수 있음. 승인 후 KISA_APPROVAL=true 로 재실행하세요."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local did_apache="false" did_nginx="false"
    webdetect_apache_present && fix_apache_user && did_apache="true"
    webdetect_nginx_present && fix_nginx_user && did_nginx="true"

    if [ "${#MODIFIED_BACKUPS[@]}" -eq 0 ]; then
        FIX_DETAIL="표준 비관리자 계정(www-data/nginx)이 없거나 설정 파일에 쓸 수 없어 조치를 수행하지 못함. 계정 생성 후 수동 조치가 필요함."
        return 2
    fi

    [ "$did_apache" = "true" ] && ! webdetect_apache_configtest && { rollback_modified; FIX_DETAIL="Apache 설정 검증 실패로 백업본으로 롤백함."; return 2; }
    [ "$did_nginx" = "true" ] && ! webdetect_nginx_configtest && { rollback_modified; FIX_DETAIL="Nginx 설정 검증 실패로 백업본으로 롤백함."; return 2; }

    [ "$did_apache" = "true" ] && { command -v systemctl >/dev/null 2>&1 && systemctl restart apache2 >/dev/null 2>&1; }
    [ "$did_nginx" = "true" ] && webdetect_nginx_reload

    FIX_DETAIL="웹 서비스 실행 계정을 표준 비관리자 계정(www-data/nginx)으로 전환함. 디렉터리 소유권은 별도 점검 필요. 변경 파일 수: ${#MODIFIED_BACKUPS[@]}"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-09 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
