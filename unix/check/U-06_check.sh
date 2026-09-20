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

do_check() {
    if [ ! -r "$PAM_SU" ]; then
        CHECK_DETAIL="${PAM_SU} 파일이 존재하지 않아 판정이 불가능함(해당 배포판에 su PAM 정책이 없을 수 있음)."
        return "$KISA_EXIT_FAIL"
    fi

    if grep -Eq '^[[:space:]]*auth[[:space:]]+(required|requisite)[[:space:]]+pam_wheel\.so' "$PAM_SU"; then
        CHECK_DETAIL="${PAM_SU} 에 pam_wheel.so 제한이 활성화되어 있어 wheel 그룹 계정만 su 사용이 가능함."
        return "$KISA_EXIT_GOOD"
    fi

    CHECK_DETAIL="${PAM_SU} 에 pam_wheel.so 제한이 설정되어 있지 않아 모든 계정이 su 명령을 시도할 수 있음."
    return "$KISA_EXIT_VULN"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
