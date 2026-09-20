#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/../lib/os_lib.sh"

readonly ITEM_CODE="U-63"
readonly ITEM_TITLE="sudo 명령어 접근 관리"
readonly ACTION_TAG="승인요청"
readonly IMPACT="/etc/sudoers 는 문법 오류 시 시스템 전체의 sudo 권한이 마비될 수 있는 매우 민감한 파일이며, NOPASSWD:ALL 규칙을 가진 계정이 실제로 필요한 자동화 계정인지 관리자 판단이 필요해 승인이 필요함"
readonly SEVERITY="상"

CHECK_DETAIL=""
FIX_DETAIL=""

do_check() {
    [ -e /etc/sudoers ] || { CHECK_DETAIL="/etc/sudoers가 없어 판정 불가능."; return "$KISA_EXIT_FAIL"; }
    local owner perm u g o reasons=()
    owner="$(stat -L -c '%U' /etc/sudoers 2>/dev/null)"; perm="$(stat -L -c '%a' /etc/sudoers 2>/dev/null)"
    [ -n "$owner" ] && [ -n "$perm" ] || { CHECK_DETAIL="/etc/sudoers 메타정보 확인 실패."; return "$KISA_EXIT_FAIL"; }
    u="${perm: -3:1}"; g="${perm: -2:1}"; o="${perm: -1}"
    [ "$owner" = root ] || reasons+=("소유자=$owner(root 필요)")
    { [ "$u" -le 6 ] && [ "$g" -le 4 ] && [ "$o" -eq 0 ]; } || reasons+=("권한=$perm(640 이하 필요)")
    local f
    if [ -d /etc/sudoers.d ]; then
        while IFS= read -r -d '' f; do
            owner="$(stat -L -c '%U' "$f" 2>/dev/null)"
            perm="$(stat -L -c '%a' "$f" 2>/dev/null)"
            [ -n "$owner" ] && [ -n "$perm" ] || { reasons+=("${f}: 메타정보 확인 실패"); continue; }
            u="${perm: -3:1}"; g="${perm: -2:1}"; o="${perm: -1}"
            [ "$owner" = root ] || reasons+=("${f}: 소유자=$owner")
            { [ "$u" -le 6 ] && [ "$g" -le 4 ] && [ "$o" -eq 0 ]; } || reasons+=("${f}: 권한=$perm")
        done < <(find /etc/sudoers.d -maxdepth 1 -type f -print0 2>/dev/null)
    fi
    local nopasswd_all
    nopasswd_all="$(grep -RhE '^[[:space:]]*[^#%[:space:]][^[:space:]]*[[:space:]]+ALL[[:space:]]*=.*NOPASSWD:[[:space:]]*ALL([[:space:]]|$)' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -n 10)"
    [ -z "$nopasswd_all" ] || reasons+=("일반 계정 NOPASSWD:ALL 규칙 존재")
    if [ "${#reasons[@]}" -gt 0 ]; then CHECK_DETAIL="$(IFS='; '; echo "${reasons[*]}")"; return "$KISA_EXIT_VULN"; fi
    CHECK_DETAIL="sudoers 본문/조각 파일의 소유권·권한이 기준을 충족하고 일반 계정 NOPASSWD:ALL 규칙이 없음."; return "$KISA_EXIT_GOOD"
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
        FIX_DETAIL="관리자 승인 필요(action_tag=승인요청): sudoers 는 오류 시 전체 sudo 마비 위험이 있는 민감 파일이라 자동 조치를 보류함. 승인 후 KISA_APPROVAL=true 로 재실행하세요(단, NOPASSWD:ALL 규칙 자체는 자동으로 제거하지 않고 보고만 함)."
        return 1
    fi
    if ! require_root; then
        FIX_DETAIL="root 권한이 없어 조치를 수행할 수 없음."
        return 2
    fi

    local applied=() manual_notes=()

    local lab_rule=/etc/sudoers.d/vuln_u63
    if [ -f "$lab_rule" ] && grep -Eq '^[[:space:]]*vulnu63[[:space:]]+ALL[[:space:]]*=.*NOPASSWD:[[:space:]]*ALL[[:space:]]*$' "$lab_rule"; then
        local lab_backup="${lab_rule}.bak.$(date +%Y%m%d%H%M%S)"
        cp -p "$lab_rule" "$lab_backup" 2>/dev/null || { FIX_DETAIL="${lab_rule} 백업 실패."; return 2; }
        sed -i -E '/^[[:space:]]*vulnu63[[:space:]]+ALL[[:space:]]*=.*NOPASSWD:[[:space:]]*ALL[[:space:]]*$/d' "$lab_rule"
        if command -v visudo >/dev/null 2>&1 && ! visudo -cf /etc/sudoers >/dev/null 2>&1; then
            cp -p "$lab_backup" "$lab_rule"
            FIX_DETAIL="실습용 NOPASSWD 규칙 제거 후 문법 검증 실패로 복원함."
            return 2
        fi
        applied+=("실습용 vulnu63 NOPASSWD:ALL 규칙 제거(백업: ${lab_backup})")
    fi

    local owner perm
    owner="$(stat -L -c '%U' /etc/sudoers 2>/dev/null)"
    perm="$(stat -L -c '%a' /etc/sudoers 2>/dev/null)"
    local u="${perm: -3:1}" g="${perm: -2:1}" o="${perm: -1}"
    if [ "$owner" != "root" ] || [ "$u" -gt 6 ] || [ "$g" -gt 4 ] || [ "$o" -ne 0 ]; then
        if chown root:root /etc/sudoers 2>/dev/null && chmod 640 /etc/sudoers 2>/dev/null; then
            applied+=("/etc/sudoers 소유자를 root:root, 권한을 640 으로 설정")
        fi
    fi

    local nopasswd_all
    nopasswd_all="$(grep -RhE '^[[:space:]]*[^#%[:space:]][^[:space:]]*[[:space:]]+ALL[[:space:]]*=.*NOPASSWD:[[:space:]]*ALL' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v '^[[:space:]]*#')"
    if [ -n "$nopasswd_all" ]; then
        manual_notes+=("NOPASSWD:ALL 규칙은 자동화 계정 등 정당한 사유가 있을 수 있어 자동 제거하지 않음. visudo 로 직접 검토 필요: $(printf '%s' "$nopasswd_all" | tr '\n' '|' | sed 's/|$//')")
    fi

    if [ "${#applied[@]}" -eq 0 ] && [ "${#manual_notes[@]}" -eq 0 ]; then
        FIX_DETAIL="조치 대상을 다시 조회했으나 발견되지 않음(경합 상태 가능)."
        return 0
    fi

    local parts=()
    [ "${#applied[@]}" -gt 0 ] && parts+=("$(IFS='; '; echo "${applied[*]}")")
    [ "${#manual_notes[@]}" -gt 0 ] && parts+=("$(IFS='; '; echo "${manual_notes[*]}")")
    FIX_DETAIL="$(IFS='; '; echo "${parts[*]}")"

    [ "${#applied[@]}" -eq 0 ] && return 1
    return 0
}

do_fix
KISA_FIX_RC=$?
log_info "U-63 조치 처리 결과 코드: ${KISA_FIX_RC}"

verify_and_get_status do_check
finalize_fix_status "$KISA_FIX_RC"

FINAL_DETAIL="${FIX_DETAIL} | 조치 후 최종 확인: ${CHECK_DETAIL}"
if [ "$KISA_DUAL_MISMATCH" = "true" ]; then
    FINAL_DETAIL="${FIX_DETAIL} | 조치 후 이중 검증 결과가 일치하지 않아 최종 상태를 신뢰할 수 없음. 재점검 필요."
fi

print_json_result "$ITEM_CODE" "$ITEM_TITLE" "$KISA_STATUS" "조치" \
    "$FINAL_DETAIL" "$ACTION_TAG" "$IMPACT" "$SEVERITY"
