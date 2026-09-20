#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-13"
readonly ITEM_TITLE="안전한 비밀번호 암호화 알고리즘 사용"
readonly ACTION_TAG="자동조치"
readonly IMPACT="login.defs 값 및 PAM 비밀번호(password) 스택의 pam_unix.so 옵션만 변경되며, 로그인(auth) 스택은 건드리지 않아 재시작이나 기존 세션 영향이 없음. 신규로 설정되는 비밀번호부터 강한 알고리즘이 적용되고 기존 해시는 유지됨"
readonly SEVERITY="상"
readonly LOGIN_DEFS="/etc/login.defs"
readonly SECURE_RE='sha512|yescrypt|sha256'

CHECK_DETAIL=""

do_check() {
    local via_defs="" via_pam=""

    if [ -r "$LOGIN_DEFS" ]; then
        via_defs="$(awk '/^[[:space:]]*ENCRYPT_METHOD[[:space:]]/{print tolower($2); exit}' "$LOGIN_DEFS")"
    fi

    local pam_candidates=(/etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth)
    for f in "${pam_candidates[@]}"; do
        [ -r "$f" ] || continue
        if grep -Eq "pam_unix\.so.*(${SECURE_RE})" "$f" 2>/dev/null; then
            via_pam="$f"
            break
        fi
    done

    if [[ "$via_defs" =~ ^(sha512|yescrypt|sha256)$ ]]; then
        CHECK_DETAIL="${LOGIN_DEFS} 의 ENCRYPT_METHOD=${via_defs} 로 안전한 알고리즘이 설정되어 있음."
        return "$KISA_EXIT_GOOD"
    fi

    if [ -n "$via_pam" ]; then
        CHECK_DETAIL="${via_pam} 의 pam_unix.so 에 안전한 해시 옵션(sha512/yescrypt 계열)이 설정되어 있음."
        return "$KISA_EXIT_GOOD"
    fi

    if [ -n "$via_defs" ]; then
        CHECK_DETAIL="${LOGIN_DEFS} 의 ENCRYPT_METHOD=${via_defs} 로 취약한(구형) 알고리즘이 설정되어 있음."
    else
        CHECK_DETAIL="ENCRYPT_METHOD 및 PAM pam_unix.so 옵션 어디에서도 안전한 해시 알고리즘 설정을 확인할 수 없음."
    fi
    return "$KISA_EXIT_VULN"
}

verify_and_get_status do_check

if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    CHECK_DETAIL="이중 검증 결과가 일치하지 않아 신뢰할 수 있는 판정을 내릴 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "점검" \
    "$CHECK_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
