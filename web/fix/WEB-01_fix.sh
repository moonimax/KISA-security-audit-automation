#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-01"
readonly ITEM_TITLE="Default 관리자 계정명 변경"
readonly ACTION_TAG="승인요청"
readonly IMPACT="관리자 계정명 변경 시 기존에 알고 있던 로그인 정보가 무효화되어 재접속 정보 갱신이 필요함"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    local users_xml
    if ! users_xml="$(webdetect_tomcat_users_xml 2>/dev/null)"; then
        CHECK_DETAIL="Tomcat tomcat-users.xml 을 찾을 수 없어 해당 없음. 양호."
        return "$KISA_EXIT_GOOD"
    fi
    if [ ! -r "$users_xml" ]; then
        CHECK_DETAIL="${users_xml} 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    local weak_found=""
    while IFS= read -r line; do
        case "$line" in
            *manager-gui*|*manager-script*|*manager-jmx*|*manager-status*)
                local uname
                uname="$(printf '%s' "$line" | sed -n 's/.*username="\([^"]*\)".*/\1/p')"
                case "$(printf '%s' "$uname" | tr '[:upper:]' '[:lower:]')" in
                    tomcat|admin|manager|root|administrator)
                        weak_found="${weak_found}${uname} "
                        ;;
                esac
                ;;
        esac
    done < <(grep -i '<user ' "$users_xml" 2>/dev/null)
    if [ -n "$weak_found" ]; then
        CHECK_DETAIL="manager 역할 계정명이 기본값(${weak_found% })으로 설정됨."
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="manager 역할 계정이 없거나 기본 계정명이 아님."
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 기본 관리자 계정명 변경은 기존 로그인 경로에 영향을 줌. 승인 후 KISA_APPROVAL=true 와 KISA_WEB01_NEW_USERNAME(새 계정명)을 함께 지정해 재실행하세요."
        return 1
    fi

    local new_user="${KISA_WEB01_NEW_USERNAME:-}"
    if [ -z "$new_user" ]; then
        FIX_DETAIL="새 관리자 계정명(KISA_WEB01_NEW_USERNAME)이 지정되지 않아 조치를 보류함. docs/override_env_vars.md 참고."
        return 1
    fi
    if ! [[ "$new_user" =~ ^[A-Za-z][A-Za-z0-9_.-]{2,63}$ ]]; then
        FIX_DETAIL="KISA_WEB01_NEW_USERNAME 값('${new_user}')이 안전한 계정명 형식(영문 시작, 영숫자/._- 3~64자)이 아니어서 조치를 보류함."
        return 1
    fi

    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local users_xml
    users_xml="$(webdetect_tomcat_users_xml 2>/dev/null)"
    if [ -z "$users_xml" ] || [ ! -w "$users_xml" ]; then
        FIX_DETAIL="tomcat-users.xml 을 쓸 수 없어 조치를 수행할 수 없음."
        return 2
    fi

    local backup
    if ! backup="$(webdetect_backup_file "$users_xml")"; then
        FIX_DETAIL="설정 파일 백업 실패로 조치를 중단함."
        return 2
    fi
    log_info "tomcat-users.xml 백업 완료: ${backup}"

    local repl
    repl="$(webdetect_sed_escape_repl "$new_user")"
    sed -i -E "s/username=\"(tomcat|admin|manager|root|administrator)\"/username=\"${repl}\"/gI" "$users_xml"

    webdetect_tomcat_restart || log_warn "Tomcat 재시작에 실패했거나 서비스가 systemd 로 관리되지 않음. 수동 재시작 필요."

    FIX_DETAIL="tomcat-users.xml 의 기본 관리자 계정명을 '${new_user}' 로 변경함. 백업: ${backup}"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-01 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
