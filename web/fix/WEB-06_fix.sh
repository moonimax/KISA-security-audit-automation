#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-06"
readonly ITEM_TITLE="웹 서비스 상위 디렉터리 접근 제한 설정"
readonly ACTION_TAG="승인요청"
readonly IMPACT="웹 서버 및 웹 서비스의 특성에 따라 접근 제어 추가가 정상 접근까지 막을 수 있음"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

apache_has_access_control() {
    local f in_root_dir="false" found_deny="false" found_root_block="false"
    local line path
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        in_root_dir="false"
        while IFS= read -r line; do
            case "$line" in
                *'<Directory'*)
                    path="$(printf '%s' "$line" | sed -n 's/.*<Directory[[:space:]]*"\{0,1\}\([^">]*\)"\{0,1\}>.*/\1/p')"
                    if [ "$path" = "/" ]; then
                        in_root_dir="true"
                        found_root_block="true"
                    else
                        in_root_dir="false"
                    fi
                    ;;
                *'</Directory>'*)
                    in_root_dir="false"
                    ;;
                *)
                    if [ "$in_root_dir" = "true" ] && printf '%s' "$line" \
                        | grep -qiE '^[[:space:]]*Require[[:space:]]+all[[:space:]]+denied'; then
                        found_deny="true"
                    fi
                    ;;
            esac
        done < "$f"
    done < <(webdetect_apache_active_confs)

    [ "$found_root_block" = "false" ] && return 1
    [ "$found_deny" = "true" ]
}

nginx_has_auth_basic() {
    local f
    while IFS= read -r f; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*auth_basic[[:space:]]' "$f" 2>/dev/null && return 0
    done < <(webdetect_nginx_active_confs)
    return 1
}

do_check() {
    if ! webdetect_any_httpd_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    local vuln="false" detail=""
    if webdetect_apache_present && ! apache_has_access_control; then
        vuln="true"; detail="${detail}Apache: 접근 제어 설정 없음. "
    fi
    if webdetect_nginx_present && ! nginx_has_auth_basic; then
        vuln="true"; detail="${detail}Nginx: 접근 제어 설정 없음. "
    fi
    CHECK_DETAIL="${detail:-접근 제어 설정 확인됨}"
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 상위 디렉터리 접근 제한은 실제 인증 계정 구성이 필요한 항목이라 자동 완결이 불가능함. 승인 후 KISA_APPROVAL=true 로 재실행하세요."
        return 1
    fi

    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local main backup
    main="$(webdetect_apache_mainconf 2>/dev/null || true)"
    if [ -z "$main" ] || [ ! -w "$main" ]; then
        FIX_DETAIL="Apache 기본 설정 파일을 변경할 수 없음."
        return 2
    fi
    backup="$(webdetect_backup_file "$main")" || return 2
    sed -i -E '/^[[:space:]]*<Directory[[:space:]]+"?\/"?>/,/^[[:space:]]*<\/Directory>/ s/^([[:space:]]*)Require[[:space:]]+all[[:space:]]+granted/\1Require all denied/I' "$main"

    if ! webdetect_apache_configtest; then
        cp -p "$backup" "$main"
        FIX_DETAIL="Apache 설정 검증 실패로 백업본으로 롤백함."
        return 2
    fi
    webdetect_apache_reload || log_warn "Apache reload 실패"
    FIX_DETAIL="파일시스템 루트 <Directory /> 접근을 Require all denied 로 제한함."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-06 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
