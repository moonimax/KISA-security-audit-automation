#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-27"
readonly ITEM_TITLE="\$HOME/.rhosts, hosts.equiv 사용 금지"
readonly ACTION_TAG="승인요청"
readonly IMPACT="파일을 즉시 삭제(rm)하지 않고 .disabled 로 이름을 바꿔 신뢰 기반 인증 기능만 무력화하는 가역적 조치이나, 극히 드물게 정상적인 클러스터/HPC 환경에서 r-계열 트러스트를 의도적으로 사용 중일 수 있어 관리자 확인이 필요함"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    if [ ! -r /etc/passwd ]; then
        CHECK_DETAIL="/etc/passwd 를 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    local rhosts_found=()
    while IFS=: read -r uname _ _ _ _ home _; do
        [ -z "$home" ] && continue
        [ -e "${home}/.rhosts" ] && rhosts_found+=("${home}/.rhosts(${uname})")
    done < /etc/passwd

    local equiv_bad=""
    if [ -e /etc/hosts.equiv ]; then
        if grep -vE '^[[:space:]]*(#|$)' /etc/hosts.equiv >/dev/null 2>&1; then
            equiv_bad="/etc/hosts.equiv(내용 존재)"
        fi
    fi

    if [ "${#rhosts_found[@]}" -gt 0 ] || [ -n "$equiv_bad" ]; then
        local parts=()
        [ "${#rhosts_found[@]}" -gt 0 ] && parts+=("$(IFS=','; echo "${rhosts_found[*]}")")
        [ -n "$equiv_bad" ] && parts+=("$equiv_bad")
        CHECK_DETAIL="신뢰 기반 인증 파일 발견: $(IFS='; '; echo "${parts[*]}")"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL=".rhosts 파일이 존재하는 계정이 없고, hosts.equiv 도 없거나 비어있음(주석 제외)."
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 신뢰 기반 인증 파일이 의도된 구성인지 확인이 필요해 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하면 파일을 삭제하지 않고 .disabled 로 이름을 변경함."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local ts renamed=0 failed=0 renamed_list=""
    ts="$(date +%Y%m%d%H%M%S)"

    while IFS=: read -r uname _ _ _ _ home _; do
        [ -z "$home" ] && continue
        local f="${home}/.rhosts"
        [ -e "$f" ] || continue
        if mv "$f" "${f}.disabled.${ts}" 2>/dev/null; then
            renamed=$((renamed + 1))
            renamed_list="${renamed_list}${renamed_list:+,}${f}"
        else
            failed=$((failed + 1))
        fi
    done < /etc/passwd

    if [ -e /etc/hosts.equiv ] && grep -vE '^[[:space:]]*(#|$)' /etc/hosts.equiv >/dev/null 2>&1; then
        if mv /etc/hosts.equiv "/etc/hosts.equiv.disabled.${ts}" 2>/dev/null; then
            renamed=$((renamed + 1))
            renamed_list="${renamed_list}${renamed_list:+,}/etc/hosts.equiv"
        else
            failed=$((failed + 1))
        fi
    fi

    log_info "신뢰 기반 인증 파일 비활성화: 성공 ${renamed}건, 실패 ${failed}건"

    if [ "$renamed" -eq 0 ] && [ "$failed" -gt 0 ]; then
        FIX_DETAIL="파일 이름 변경에 모두 실패함(${failed}건)."
        return 2
    fi
    if [ "$renamed" -eq 0 ]; then
        FIX_DETAIL="조치 대상 파일을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi

    FIX_DETAIL="${renamed_list} 를 '.disabled.${ts}' 접미사로 이름 변경하여 비활성화함(삭제 없음, 실패 ${failed}건)."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-27 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
