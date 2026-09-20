#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-07"
readonly ITEM_TITLE="불필요한 계정 제거"
readonly ACTION_TAG="승인요청"
readonly IMPACT="userdel 은 계정 및 홈 디렉토리 데이터를 삭제하는 파괴적 작업이며, 어떤 계정이 실제로 불필요한지는 업무 맥락에 대한 관리자의 주관적 판단이 반드시 필요함"
readonly SEVERITY="하"
readonly SUSPECT_PATTERN="^(test[0-9]*|guest[0-9]*|temp|temporary|demo|backdoor)$"
readonly NOLOGIN_SHELL="$(command -v nologin 2>/dev/null || printf '/usr/sbin/nologin')"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    if [ ! -r /etc/passwd ]; then
        CHECK_DETAIL="/etc/passwd 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    local suspects
    suspects="$(awk -F: -v pat="$SUSPECT_PATTERN" \
        'BEGIN{IGNORECASE=1} tolower($1) ~ pat && $7 !~ /(nologin|false)$/ {print $1}' \
        /etc/passwd | tr '\n' ',' | sed 's/,$//')"
    if [ -n "$suspects" ]; then
        CHECK_DETAIL="로그인 가능한 임시/테스트성 의심 계정 발견: ${suspects}"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="테스트/임시 성격의 로그인 가능 계정이 발견되지 않음."
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

    if [ "$ACTION_TAG" = "승인요청" ] && ! is_approved; then
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 계정 삭제 대상 여부는 업무 맥락 판단이 필요하고 userdel 은 파괴적 변경이라 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하면 대상 계정을 잠금/만료 처리하며, 최종 삭제는 관리자가 수동으로 결정해야 함."
        return 1
    fi

    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local accounts
    accounts="$(awk -F: -v pat="$SUSPECT_PATTERN" \
        'BEGIN{IGNORECASE=1} tolower($1) ~ pat && $7 !~ /(nologin|false)$/ {print $1}' \
        /etc/passwd)"

    if [ -z "$accounts" ]; then
        FIX_DETAIL="조치 대상 계정을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi

    local locked_list="" failed_list=""
    while IFS= read -r acct; do
        [ -z "$acct" ] && continue
        local ok=1
        if command -v usermod >/dev/null 2>&1; then
            usermod -L -s "$NOLOGIN_SHELL" "$acct" 2>/dev/null && ok=0
        fi
        if command -v chage >/dev/null 2>&1; then
            chage -E 0 "$acct" 2>/dev/null || ok=$((ok))
        fi
        if [ "$ok" -eq 0 ]; then
            log_info "임시/테스트 의심 계정 잠금+만료 처리: ${acct}"
            locked_list="${locked_list}${locked_list:+,}${acct}"
        else
            log_error "임시/테스트 의심 계정 잠금 실패: ${acct}"
            failed_list="${failed_list}${failed_list:+,}${acct}"
        fi
    done <<< "$accounts"

    if [ -n "$failed_list" ]; then
        FIX_DETAIL="잠금 처리 실패 계정: ${failed_list}. 성공: ${locked_list:-없음}."
        return 2
    fi

    FIX_DETAIL="의심 계정(${locked_list})을 잠금 및 즉시 만료(chage -E 0) 처리함(userdel 미실행). 계정 및 홈 디렉토리의 최종 삭제 여부는 관리자가 실제 사용 이력을 확인한 뒤 수동으로 결정해야 함."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-07 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
