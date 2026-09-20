#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-09"
readonly ITEM_TITLE="불필요하거나 계정과 연결되지 않은 그룹 제거"
readonly ACTION_TAG="승인요청"
readonly IMPACT="계정과 연결되지 않은 그룹도 서비스 예약 그룹일 수 있어 관리자 지정 목록만 groupdel로 삭제함"
readonly SEVERITY="하"

CHECK_DETAIL=""
FIX_DETAIL=""

_find_unlinked_groups() {
    awk -F: '
        NR==FNR { primary[$4]=1; next }
        !($3 in primary) && $4=="" { print $1 "(gid=" $3 ")" }
    ' /etc/passwd /etc/group
}

do_check() {
    if [ ! -r /etc/passwd ] || [ ! -r /etc/group ]; then
        CHECK_DETAIL="/etc/passwd 또는 /etc/group 을 읽을 수 없어 판정이 불가능함."
        return "$KISA_EXIT_FAIL"
    fi
    local orphans
    orphans="$(_find_unlinked_groups | tr '\n' ',' | sed 's/,$//')"
    if [ -n "$orphans" ]; then
        CHECK_DETAIL="기본 GID나 보조 구성원으로 어떤 계정과도 연결되지 않은 그룹 발견(업무상 필요 여부 확인 필요): $orphans"
        return "$KISA_EXIT_VULN"
    fi
    CHECK_DETAIL="/etc/group에서 계정과 연결되지 않은 그룹이 발견되지 않음."
    return "$KISA_EXIT_GOOD"
}

do_fix() {
    do_check
    local current=$?
    [ "$current" -eq "$KISA_EXIT_GOOD" ] && { FIX_DETAIL="이미 양호 상태로 조치가 필요하지 않음."; return 0; }
    [ "$current" -eq "$KISA_EXIT_FAIL" ] && { FIX_DETAIL="조치 대상 상태를 확인할 수 없어 조치를 수행하지 않음."; return 2; }
    if [ "$ACTION_TAG" = "승인요청" ] && ! is_approved; then
        FIX_DETAIL="관리자 승인 필요. 계정과 연결되지 않았더라도 서비스 예약 그룹일 수 있으므로 KISA_U09_REMOVE_GROUPS에 검토 완료한 그룹명을 지정해야 함."
        return 1
    fi
    require_root || { FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."; return 2; }
    local requested="${KISA_U09_REMOVE_GROUPS:-}"
    if [ -z "$requested" ]; then
        FIX_DETAIL="부분 조치/수동 조치 필요: 삭제할 그룹을 자동 추정하지 않음. KISA_U09_REMOVE_GROUPS='group1,group2' 지정 필요."
        return 1
    fi
    local orphan_names
    orphan_names="$(_find_unlinked_groups | sed -E 's/\\(gid=[0-9]+\\)$//')"
    local removed="" skipped="" failed="" group
    IFS=',' read -r -a groups <<< "$requested"
    for group in "${groups[@]}"; do
        group="$(printf '%s' "$group" | tr -d '[:space:]')"
        [ -n "$group" ] || continue
        if ! printf '%s\n' "$orphan_names" | grep -Fxq "$group"; then
            skipped="${skipped}${skipped:+,}$group"
            continue
        fi
        if command -v groupdel >/dev/null 2>&1 && groupdel "$group" 2>/dev/null; then
            removed="${removed}${removed:+,}$group"
        else
            failed="${failed}${failed:+,}$group"
        fi
    done
    [ -z "$failed" ] || { FIX_DETAIL="그룹 삭제 실패: $failed. 삭제 완료: ${removed:-없음}."; return 2; }
    local remaining
    remaining="$(_find_unlinked_groups | tr '\n' ',' | sed 's/,$//')"
    if [ -n "$remaining" ]; then
        FIX_DETAIL="부분 조치/수동 조치 필요: 삭제 완료 ${removed:-없음}, 요청했으나 대상이 아닌 그룹 ${skipped:-없음}, 미검토 잔여 그룹: $remaining"
        return 1
    fi
    FIX_DETAIL="검토 지정된 미연결 그룹 삭제 완료: $removed."
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-09 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
