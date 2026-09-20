#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-08"
readonly ITEM_TITLE="관리자 그룹에 최소한의 계정 포함"
readonly ACTION_TAG="승인요청"
readonly IMPACT="root 권한 그룹(gid 0)에서 계정을 제외하는 작업으로, 어떤 계정을 남겨야 하는지는 운영 정책에 대한 관리자의 판단이 필요함. 잘못 제외 시 정상 운영자의 관리자 권한이 상실될 수 있음"
readonly SEVERITY="중"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    if [ ! -r /etc/group ]; then
        CHECK_DETAIL="/etc/group 을 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    local root_group_line members
    root_group_line="$(awk -F: '$3==0 {print; exit}' /etc/group)"
    if [ -z "$root_group_line" ]; then
        CHECK_DETAIL="/etc/group 에서 GID 0 그룹을 찾을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    members="$(printf '%s' "$root_group_line" | awk -F: '{print $4}')"
    if [ -n "$members" ]; then
        CHECK_DETAIL="GID 0(관리자) 그룹에 root 외 부가 계정이 포함되어 있음: ${members}"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="GID 0(관리자) 그룹의 부가 멤버 목록이 비어 있음."
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): 어떤 계정을 관리자 그룹에서 제외해도 되는지 운영 정책 판단이 필요해 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하세요."
        return 1
    fi

    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi
    if ! command -v gpasswd >/dev/null 2>&1; then
        FIX_DETAIL="gpasswd 명령을 찾을 수 없어 조치를 수행할 수 없음."
        return 2
    fi

    local root_group_name root_group_line members
    root_group_line="$(awk -F: '$3==0 {print; exit}' /etc/group)"
    root_group_name="$(printf '%s' "$root_group_line" | awk -F: '{print $1}')"
    members="$(printf '%s' "$root_group_line" | awk -F: '{print $4}')"

    if [ -z "$members" ]; then
        FIX_DETAIL="조치 대상 멤버를 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi

    local backup="/etc/group.bak.$(date +%Y%m%d%H%M%S)"
    cp -p /etc/group "$backup" 2>/dev/null
    log_info "/etc/group 백업 완료: ${backup}"

    local removed_list="" failed_list=""
    IFS=',' read -ra member_arr <<< "$members"
    for m in "${member_arr[@]}"; do
        [ -z "$m" ] && continue
        if gpasswd -d "$m" "$root_group_name" >/dev/null 2>&1; then
            log_info "관리자 그룹(${root_group_name})에서 계정 제외: ${m}"
            removed_list="${removed_list}${removed_list:+,}${m}"
        else
            log_error "관리자 그룹에서 계정 제외 실패: ${m}"
            failed_list="${failed_list}${failed_list:+,}${m}"
        fi
    done

    if [ -n "$failed_list" ]; then
        FIX_DETAIL="제외 실패 계정: ${failed_list}. 성공: ${removed_list:-없음}. 백업: ${backup}"
        return 2
    fi

    FIX_DETAIL="관리자 그룹(${root_group_name})에서 계정(${removed_list})을 제외함(계정 자체는 삭제되지 않음, 그룹 멤버십만 해제). 백업: ${backup}"
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-08 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
