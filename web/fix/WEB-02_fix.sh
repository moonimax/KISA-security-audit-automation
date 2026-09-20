#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-02"
readonly ITEM_TITLE="취약한 비밀번호 사용 제한"
readonly ACTION_TAG="승인요청"
readonly IMPACT="비밀번호 변경 시 기존 관리자 세션 및 자동화 스크립트가 사용하던 인증 정보가 무효화됨"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    local users_xml
    if ! users_xml="$(webdetect_tomcat_users_xml 2>/dev/null)"; then
        CHECK_DETAIL="Tomcat tomcat-users.xml 을 찾을 수 없어 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    if [ ! -r "$users_xml" ]; then
        CHECK_DETAIL="${users_xml} 를 읽을 수 없음."
        return "$KISA_EXIT_FAIL"
    fi
    local weak_found="" manager_found="false"
    while IFS= read -r line; do
        case "$line" in
            *manager-gui*|*manager-script*|*manager-jmx*|*manager-status*)
                manager_found="true"
                local uname pass pass_lc
                uname="$(printf '%s' "$line" | sed -n 's/.*username="\([^"]*\)".*/\1/p')"
                pass="$(printf '%s' "$line" | sed -n 's/.*password="\([^"]*\)".*/\1/p')"
                pass_lc="$(printf '%s' "$pass" | tr '[:upper:]' '[:lower:]')"
                if [ -z "$pass" ] || [ "$pass" = "$uname" ]; then
                    weak_found="${weak_found}${uname} "
                else
                    case "$pass_lc" in
                        tomcat|admin|password|123456|changeit|manager|admin123|tomcat123|s3cret)
                            weak_found="${weak_found}${uname} " ;;
                        *) [ "${#pass}" -lt 8 ] && weak_found="${weak_found}${uname} " ;;
                    esac
                fi
                ;;
        esac
    done < <(grep -i '<user ' "$users_xml" 2>/dev/null)
    if [ -n "$weak_found" ]; then
        CHECK_DETAIL="취약한 비밀번호 사용 계정: ${weak_found% }"
        return "$KISA_EXIT_VULN"
    fi
    [ "$manager_found" = "false" ] && CHECK_DETAIL="manager 역할 계정 없음." || CHECK_DETAIL="비밀번호 복잡도 기준 만족."
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 비밀번호 변경은 기존 인증 정보를 무효화함. 승인 후 KISA_APPROVAL=true 와 KISA_WEB02_NEW_PASSWORD 를 함께 지정해 재실행하세요."
        return 1
    fi

    local new_pw="${KISA_WEB02_NEW_PASSWORD:-}"
    if [ -z "$new_pw" ]; then
        FIX_DETAIL="새 비밀번호(KISA_WEB02_NEW_PASSWORD)가 지정되지 않아 조치를 보류함. docs/override_env_vars.md 참고."
        return 1
    fi
    if [ "${#new_pw}" -lt 8 ]; then
        FIX_DETAIL="KISA_WEB02_NEW_PASSWORD 가 8자 미만이어서 조치를 보류함(KISA 비밀번호 설정 기준 미달)."
        return 1
    fi
    local classes=0
    [[ "$new_pw" =~ [A-Z] ]] && classes=$((classes + 1))
    [[ "$new_pw" =~ [a-z] ]] && classes=$((classes + 1))
    [[ "$new_pw" =~ [0-9] ]] && classes=$((classes + 1))
    [[ "$new_pw" =~ [^A-Za-z0-9] ]] && classes=$((classes + 1))
    if [ "$classes" -lt 2 ]; then
        FIX_DETAIL="KISA_WEB02_NEW_PASSWORD 가 문자 종류 2종류 이상을 조합하지 않아 조치를 보류함."
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
    repl="$(webdetect_sed_escape_repl "$new_pw")"
    awk -v repl="$repl" '
        /<user / && /manager-(gui|script|jmx|status)/ {
            sub(/password="[^"]*"/, "password=\"" repl "\"")
        }
        { print }
    ' "$users_xml" > "${users_xml}.kisa_tmp" && mv "${users_xml}.kisa_tmp" "$users_xml"

    webdetect_tomcat_restart || log_warn "Tomcat 재시작에 실패했거나 서비스가 systemd 로 관리되지 않음. 수동 재시작 필요."

    FIX_DETAIL="tomcat-users.xml 의 manager 역할 계정 비밀번호를 변경함. 백업: ${backup}"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-02 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
