#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"
source "${SCRIPT_DIR}/../lib/web_detect.sh"

readonly ITEM_CODE="WEB-24"
readonly ITEM_TITLE="별도의 업로드 경로 사용 및 권한 설정"
readonly ACTION_TAG="승인요청"
readonly IMPACT="애플리케이션이 실제 사용하는 업로드 경로 파악이 필요해 지정된 경로 외에는 자동 판단이 불가능함"
readonly SEVERITY="중"

CHECK_DETAIL=""
FIX_DETAIL=""

find_writable_upload_dirs() {
    local root="$1"
    [ -d "$root" ] || return 0
    local d
    for d in uploads upload files; do
        local p="${root%/}/$d"
        if [ -d "$p" ]; then
            local perm
            perm="$(stat -c '%a' "$p" 2>/dev/null)"
            if [ -n "$perm" ]; then
                local other="${perm: -1}"
                case "$other" in
                    2|3|6|7) printf '%s(perm=%s)\n' "$p" "$perm" ;;
                esac
            fi
        fi
    done
}

do_check() {
    if ! webdetect_apache_present && ! webdetect_nginx_present; then
        CHECK_DETAIL="Apache/Nginx 가 설치되어 있지 않아 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    fi
    local found=""
    webdetect_apache_present && found="${found}$(find_writable_upload_dirs "$(webdetect_apache_docroot)")"$'\n'
    webdetect_nginx_present && found="${found}$(find_writable_upload_dirs "$(webdetect_nginx_docroot)")"$'\n'
    found="$(printf '%s' "$found" | grep -v '^$' || true)"
    if [ -n "$found" ]; then
        CHECK_DETAIL="world-writable 업로드 디렉터리 후보: $(printf '%s' "$found" | tr '\n' ' ')"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="world-writable 업로드 디렉터리 후보 없음."
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 실제 사용 중인 업로드 경로 지정이 필요함. 승인 후 KISA_APPROVAL=true 와 KISA_WEB24_UPLOAD_DIR(대상 절대경로)를 함께 지정해 재실행하세요."
        return 1
    fi

    local target="${KISA_WEB24_UPLOAD_DIR:-}"
    if [ -z "$target" ]; then
        if webdetect_apache_present; then
            target="$(find_writable_upload_dirs "$(webdetect_apache_docroot)" | head -n1 | sed -E 's/\(perm=.*$//')"
        fi
        if [ -z "$target" ] && webdetect_nginx_present; then
            target="$(find_writable_upload_dirs "$(webdetect_nginx_docroot)" | head -n1 | sed -E 's/\(perm=.*$//')"
        fi
    fi
    if [ -z "$target" ]; then
        FIX_DETAIL="취약한 업로드 디렉터리 후보를 자동 발견하지 못함."
        return 1
    fi
    if [ ! -d "$target" ]; then
        FIX_DETAIL="지정된 경로(${target})가 대상 호스트에 디렉터리로 존재하지 않아 조치를 보류함."
        return 1
    fi

    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local runuser=""
    if id -u www-data >/dev/null 2>&1; then runuser="www-data"; elif id -u nginx >/dev/null 2>&1; then runuser="nginx"; fi

    if ! chmod 750 "$target" 2>/dev/null; then
        FIX_DETAIL="${target} 권한 변경(chmod)에 실패함."
        return 2
    fi
    if [ -n "$runuser" ]; then
        chown "${runuser}:${runuser}" "$target" 2>/dev/null || log_warn "chown 실패(권한 변경은 완료됨)"
    fi

    FIX_DETAIL="지정된 업로드 경로(${target})의 권한을 750${runuser:+, 소유자를 ${runuser}}로 변경함."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "WEB-24 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
