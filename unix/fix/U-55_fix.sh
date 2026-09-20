#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-55"
readonly ITEM_TITLE="FTP 계정 shell 제한"
readonly ACTION_TAG="자동조치"
readonly IMPACT="대상 계정의 로그인 셸만 nologin으로 변경되며 서비스 재시작이 불필요함. usermod -s 로 즉시 되돌릴 수 있는 가역적 변경임"
readonly SEVERITY="중"

CHECK_DETAIL=""
FIX_DETAIL=""

_find_user_list() {
    for f in /etc/vsftpd.user_list /etc/vsftpd/user_list /etc/vsftpd/vsftpd.user_list; do
        [ -r "$f" ] && { printf '%s' "$f"; return 0; }
    done
    return 1
}

_resolve_nologin_shell() {
    for s in /usr/sbin/nologin /sbin/nologin /bin/false; do
        [ -x "$s" ] && { printf '%s' "$s"; return 0; }
    done
    return 1
}

do_check() {
    local ulist
    ulist="$(_find_user_list)" || {
        CHECK_DETAIL="vsftpd 사용자 목록 파일을 찾을 수 없어 해당 없음(양호)."
        return "$KISA_EXIT_GOOD"
    }
    if [ ! -r /etc/passwd ]; then
        CHECK_DETAIL="/etc/passwd 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    local offenders=()
    while IFS= read -r acct; do
        acct="$(printf '%s' "$acct" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        [ -z "$acct" ] && continue
        [[ "$acct" == \#* ]] && continue
        local shell
        shell="$(awk -F: -v a="$acct" '$1==a{print $7}' /etc/passwd)"
        [ -z "$shell" ] && continue
        [[ "$shell" =~ (nologin|false)$ ]] || offenders+=("${acct}(${shell})")
    done < "$ulist"
    if [ "${#offenders[@]}" -gt 0 ]; then
        CHECK_DETAIL="${ulist} 에 명시된 계정 중 대화형 셸을 가진 계정 발견: $(IFS=','; echo "${offenders[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="${ulist} 에 명시된 모든 계정이 nologin/false 셸을 사용 중임."
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
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi
    if ! command -v usermod >/dev/null 2>&1; then
        FIX_DETAIL="usermod 명령을 찾을 수 없어 조치를 수행할 수 없음."
        return 2
    fi

    local nologin_shell
    nologin_shell="$(_resolve_nologin_shell)" || {
        FIX_DETAIL="사용 가능한 nologin 셸을 찾을 수 없어 조치를 수행할 수 없음."
        return 2
    }

    local ulist
    ulist="$(_find_user_list)" || {
        FIX_DETAIL="조치 대상 목록 파일을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    }

    local changed_list="" failed_list=""
    while IFS= read -r acct; do
        acct="$(printf '%s' "$acct" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        [ -z "$acct" ] && continue
        [[ "$acct" == \#* ]] && continue
        local shell
        shell="$(awk -F: -v a="$acct" '$1==a{print $7}' /etc/passwd)"
        [ -z "$shell" ] && continue
        [[ "$shell" =~ (nologin|false)$ ]] && continue
        if usermod -s "$nologin_shell" "$acct" 2>/dev/null; then
            log_info "FTP 계정 ${acct} 셸을 ${nologin_shell} 로 변경함."
            changed_list="${changed_list}${changed_list:+,}${acct}"
        else
            log_error "FTP 계정 ${acct} 셸 변경 실패."
            failed_list="${failed_list}${failed_list:+,}${acct}"
        fi
    done < "$ulist"

    if [ -n "$failed_list" ]; then
        FIX_DETAIL="셸 변경 실패 계정: ${failed_list}. 성공: ${changed_list:-없음}."
        return 2
    fi
    if [ -z "$changed_list" ]; then
        FIX_DETAIL="조치 대상 계정을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi

    FIX_DETAIL="FTP 계정(${changed_list})의 로그인 셸을 ${nologin_shell} 로 변경함."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-55 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
