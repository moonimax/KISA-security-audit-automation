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
FIX_DETAIL=""

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
        CHECK_DETAIL="ENCRYPT_METHOD=${via_defs} 로 안전한 알고리즘이 설정되어 있음."
        return "$KISA_EXIT_GOOD"
    fi
    if [ -n "$via_pam" ]; then
        CHECK_DETAIL="${via_pam} 의 pam_unix.so 에 안전한 해시 옵션이 설정되어 있음."
        return "$KISA_EXIT_GOOD"
    fi
    if [ -n "$via_defs" ]; then
        CHECK_DETAIL="ENCRYPT_METHOD=${via_defs} 로 취약한 알고리즘이 설정되어 있음."
    else
        CHECK_DETAIL="안전한 해시 알고리즘 설정을 확인할 수 없음."
    fi
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
        FIX_DETAIL="조치 대상 상태를 확인할 수 없어 조치를 수행하지 않음."
        return 2
    fi

    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local applied=()

    if [ -w "$LOGIN_DEFS" ]; then
        local backup="${LOGIN_DEFS}.bak.$(date +%Y%m%d%H%M%S)"
        cp -p "$LOGIN_DEFS" "$backup" 2>/dev/null
        if grep -qE '^[[:space:]]*ENCRYPT_METHOD[[:space:]]' "$LOGIN_DEFS"; then
            sed -i -E 's/^[[:space:]]*ENCRYPT_METHOD[[:space:]]+.*/ENCRYPT_METHOD SHA512/' "$LOGIN_DEFS"
        else
            printf '\nENCRYPT_METHOD SHA512\n' >> "$LOGIN_DEFS"
        fi
        applied+=("${LOGIN_DEFS} ENCRYPT_METHOD=SHA512 (백업: ${backup})")
    fi

    local pam_candidates=(/etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth)
    for f in "${pam_candidates[@]}"; do
        [ -r "$f" ] || continue
        grep -Eq 'pam_unix\.so' "$f" || continue
        if grep -Eq "pam_unix\.so.*(${SECURE_RE})" "$f"; then
            continue
        fi
        local backup="${f}.bak.$(date +%Y%m%d%H%M%S)"
        cp -p "$f" "$backup" 2>/dev/null
        sed -i -E "/^[[:space:]]*password[[:space:]]+.*pam_unix\.so/ s/pam_unix\.so/pam_unix.so sha512/" "$f"
        applied+=("${f} 의 password pam_unix.so 에 sha512 옵션 추가 (백업: ${backup})")
    done

    if [ "${#applied[@]}" -eq 0 ]; then
        FIX_DETAIL="login.defs 및 PAM 파일에 쓰기 권한이 없거나 대상을 찾지 못해 조치를 수행하지 못함."
        return 2
    fi

    FIX_DETAIL="$(IFS='; '; echo "${applied[*]}")"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-13 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
