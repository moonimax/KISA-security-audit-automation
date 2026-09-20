#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-06"
readonly ITEM_TITLE="사용자 계정 su 기능 제한"
readonly ACTION_TAG="자동조치"
readonly IMPACT="su 명령어에만 국한된 PAM 설정 추가로, 서비스 재시작이 불필요하고 SSH 등 기존 로그인 세션에는 영향이 없음. 단, wheel 그룹에 속하지 않은 계정은 이후 su 사용이 제한됨"
readonly SEVERITY="중"
readonly PAM_SU="/etc/pam.d/su"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    if [ ! -r "$PAM_SU" ]; then
        CHECK_DETAIL="${PAM_SU} 파일이 존재하지 않아 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    if grep -Eq '^[[:space:]]*auth[[:space:]]+(required|requisite)[[:space:]]+pam_wheel\.so' "$PAM_SU"; then
        CHECK_DETAIL="${PAM_SU} 에 pam_wheel.so 제한이 활성화되어 있음."
        return "$KISA_EXIT_GOOD"
    fi
    CHECK_DETAIL="${PAM_SU} 에 pam_wheel.so 제한이 설정되어 있지 않음."
    return "$KISA_EXIT_VULN"
}

do_fix() {
    do_check
    local current=$?

    if [ "$current" -eq "$KISA_EXIT_GOOD" ]; then
        FIX_DETAIL="이미 양호 상태로 조치가 필요하지 않음."
        return 0
    fi
    if [ "$current" -eq "$KISA_EXIT_FAIL" ]; then
        FIX_DETAIL="조치 대상 상태를 확인할 수 없어 조치를 수행하지 않음(${PAM_SU} 부재)."
        return 2
    fi

    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local wheel_members
    wheel_members="$(getent group wheel 2>/dev/null | awk -F: '{print $4}')"
    if [ -z "$wheel_members" ] && ! id -nG root 2>/dev/null | grep -qw wheel; then
        if command -v usermod >/dev/null 2>&1 && getent group wheel >/dev/null 2>&1; then
            usermod -aG wheel root 2>/dev/null
            log_info "wheel 그룹이 비어 있어 root 를 wheel 그룹에 추가함."
        fi
    fi

    local backup="${PAM_SU}.bak.$(date +%Y%m%d%H%M%S)"
    if ! cp -p "$PAM_SU" "$backup" 2>/dev/null; then
        FIX_DETAIL="설정 파일 백업 실패로 조치를 중단함."
        return 2
    fi
    log_info "${PAM_SU} 백업 완료: ${backup}"

    printf 'auth\t\trequired\tpam_wheel.so use_uid\n' >> "$PAM_SU"

    FIX_DETAIL="${PAM_SU} 에 'auth required pam_wheel.so use_uid' 라인을 추가함. 백업: ${backup}"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-06 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
